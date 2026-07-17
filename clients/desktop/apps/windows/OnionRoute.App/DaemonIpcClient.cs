using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.Principal;
using Google.Protobuf;
using Onionroute.Desktop.Ipc.V1;

namespace OnionRoute.App;

internal sealed class DaemonIpcClient : IDisposable
{
    private const int MaxFrame = 64 * 1024;
    private readonly SemaphoreSlim writeLock = new(1, 1);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<Response>> pending = new();
    private NamedPipeClientStream? pipe;
    private ulong sequence;

    public event EventHandler<StateSnapshot>? StateChanged;
    public event EventHandler<bool>? ConnectionChanged;

    public async Task RunReconnectLoopAsync(CancellationToken cancellation)
    {
        var delay = TimeSpan.FromMilliseconds(250);
        while (!cancellation.IsCancellationRequested)
        {
            NamedPipeClientStream? candidate = null;
            try
            {
                candidate = new NamedPipeClientStream(
                    ".", "OnionRoute.Control.v1", PipeDirection.InOut,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough,
                    TokenImpersonationLevel.Identification);
                await candidate.ConnectAsync(5_000, cancellation);
                WindowsPeerVerifier.VerifyDaemon(candidate.SafePipeHandle);
                sequence = 0;
                delay = TimeSpan.FromMilliseconds(250);
                await SendHelloAsync(candidate, cancellation);
                pipe = candidate;
                var reader = ReadEventsAsync(candidate, cancellation);
                var initial = await SendCommandAsync(
                    new Request { GetState = new GetStateRequest() }, cancellation);
                EnsureAccepted(initial);
                PublishState(initial.State);
                ConnectionChanged?.Invoke(this, true);
                await reader;
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
                break;
            }
            catch
            {
                candidate?.Dispose();
                pipe = null;
                FailPending(new IOException("Protection service connection closed"));
                ConnectionChanged?.Invoke(this, false);
                await Task.Delay(delay, cancellation);
                delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 5_000));
            }
        }
    }

    public async Task<Response> SendCommandAsync(Request command, CancellationToken cancellation)
    {
        var current = pipe ?? throw new InvalidOperationException("Protection service is reconnecting");
        var envelope = NewEnvelope();
        envelope.Request = command;
        var key = Convert.ToBase64String(envelope.RequestId.Span);
        var completion = new TaskCompletionSource<Response>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!pending.TryAdd(key, completion)) throw new InvalidOperationException("Duplicate request identifier");
        try
        {
            await WriteFrameAsync(current, envelope, cancellation);
            return await completion.Task.WaitAsync(TimeSpan.FromSeconds(15), cancellation);
        }
        finally { pending.TryRemove(key, out _); }
    }

    public async Task SendAcceptedCommandAsync(Request command, CancellationToken cancellation)
    {
        var response = await SendCommandAsync(command, cancellation);
        EnsureAccepted(response);
        PublishState(response.State);
    }

    public async Task SendConfirmedCommandAsync(
        Request command,
        CriticalAction expectedAction,
        CancellationToken cancellation)
    {
        var challenge = await SendCommandAsync(command, cancellation);
        if (challenge.Status != ResponseStatus.ConfirmationRequired ||
            challenge.Confirmation?.Action != expectedAction ||
            challenge.Confirmation.ConfirmationId.Length != 16)
            throw new InvalidOperationException("Protection service did not issue a valid confirmation");
        command.ConfirmationId = challenge.Confirmation.ConfirmationId;
        var response = await SendCommandAsync(command, cancellation);
        EnsureAccepted(response);
        PublishState(response.State);
    }

    private async Task SendHelloAsync(Stream stream, CancellationToken cancellation)
    {
        var nonce = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(nonce);
        var hello = NewEnvelope();
        hello.ClientHello = new ClientHello
        {
            SupportedVersions = new ProtocolVersionRange
            {
                Minimum = new ProtocolVersion { Major = 1, Minor = 0 },
                Maximum = new ProtocolVersion { Major = 1, Minor = 0 }
            },
            ProcessNonce = ByteString.CopyFrom(nonce),
            EventWindow = 64
        };
        hello.ClientHello.RequestedTopics.Add(EventTopic.TunnelState);
        hello.ClientHello.RequestedTopics.Add(EventTopic.LeakProtection);
        await WriteFrameAsync(stream, hello, cancellation);
    }

    private async Task ReadEventsAsync(Stream stream, CancellationToken cancellation)
    {
        var prefix = new byte[4];
        while (!cancellation.IsCancellationRequested)
        {
            await stream.ReadExactlyAsync(prefix, cancellation);
            var length = BinaryPrimitives.ReadUInt32BigEndian(prefix);
            if (length == 0 || length > MaxFrame) throw new InvalidDataException("Invalid IPC frame length");
            var payload = new byte[length];
            await stream.ReadExactlyAsync(payload, cancellation);
            var envelope = Envelope.Parser.ParseFrom(payload);
            if (envelope.Version?.Major != 1 || envelope.RequestId.Length != 16 || envelope.Sequence == 0)
                throw new InvalidDataException("Invalid IPC envelope");
            if (envelope.Response is { } response &&
                pending.TryRemove(Convert.ToBase64String(envelope.RequestId.Span), out var completion))
                completion.TrySetResult(response);
            if (envelope.Event is { } daemonEvent)
            {
                if (daemonEvent.StateChanged is { } state)
                    StateChanged?.Invoke(this, state);
                await AcknowledgeEventAsync(stream, daemonEvent.EventSequence, cancellation);
            }
        }
    }

    private async Task AcknowledgeEventAsync(
        Stream stream,
        ulong eventSequence,
        CancellationToken cancellation)
    {
        if (eventSequence == 0)
            throw new InvalidDataException("Invalid daemon event sequence");
        var acknowledgement = NewEnvelope();
        acknowledgement.Request = new Request
        {
            AcknowledgeEvents = new AcknowledgeEventsRequest
            {
                ThroughSequence = eventSequence
            }
        };
        await WriteFrameAsync(stream, acknowledgement, cancellation);
    }

    private async Task WriteFrameAsync(Stream stream, Envelope envelope, CancellationToken cancellation)
    {
        await writeLock.WaitAsync(cancellation);
        try
        {
            envelope.Sequence = checked(++sequence);
            var payload = envelope.ToByteArray();
            if (payload.Length > MaxFrame) throw new InvalidDataException("IPC frame exceeds hard limit");
            var prefix = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(prefix, checked((uint)payload.Length));
            await stream.WriteAsync(prefix, cancellation);
            await stream.WriteAsync(payload, cancellation);
            await stream.FlushAsync(cancellation);
        }
        finally { writeLock.Release(); }
    }

    private Envelope NewEnvelope()
    {
        var requestId = new byte[16];
        System.Security.Cryptography.RandomNumberGenerator.Fill(requestId);
        return new Envelope
        {
            Version = new ProtocolVersion { Major = 1, Minor = 0 },
            RequestId = ByteString.CopyFrom(requestId),
            Sequence = 0
        };
    }

    private void PublishState(StateSnapshot? state)
    {
        if (state is not null)
            StateChanged?.Invoke(this, state);
    }

    private static void EnsureAccepted(Response response)
    {
        if (response.Status != ResponseStatus.Ok)
            throw new InvalidOperationException(
                $"Protection service rejected the request ({response.ErrorCode})");
    }

    public void Dispose()
    {
        pipe?.Dispose();
        FailPending(new ObjectDisposedException(nameof(DaemonIpcClient)));
        writeLock.Dispose();
    }

    private void FailPending(Exception error)
    {
        foreach (var entry in pending)
            if (pending.TryRemove(entry.Key, out var completion)) completion.TrySetException(error);
    }
}
