using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Onionroute.Desktop.Ipc.V1;

namespace OnionRoute.App;

public sealed partial class MainWindow : Window
{
    private readonly CancellationTokenSource lifetime = new();
    private readonly DaemonIpcClient daemon = new();

    public MainWindow()
    {
        InitializeComponent();
#if ONIONROUTE_LOCAL_PROTOTYPE
        Title = "OnionRoute — Direct Tor user-mode prototype";
        PrototypeBoundaryBar.IsOpen = true;
        PrototypeBoundaryBar.Visibility = Visibility.Visible;
        KillSwitchValue.Text = "Not system-wide";
        BlockedLeaksValue.Text = "Not measured system-wide";
        UdpValue.Text = "Unsupported by local proxy";
        UdpPolicyBar.Title = "UDP is outside this prototype";
        UdpPolicyBar.Message = "The local SOCKS proxy accepts TCP CONNECT only. Other Windows applications can still send UDP directly.";
        CountrySelector.IsEnabled = false;
        CountryHelpText.Text = "Exit-country selection requires the private gateway service and is unavailable in Direct Tor mode.";
        StandardModeOption.IsChecked = false;
        StandardModeOption.IsEnabled = false;
        EnhancedModeOption.IsEnabled = false;
        MaximumModeOption.IsEnabled = false;
        DirectTorModeOption.IsChecked = true;
        RouteSummaryText.Text = "Application → local SOCKS5 proxy → Tor → public Tor exit/onion service";
        RouteHelpText.Text = "The daemon reports ready only after a live v3 onion probe succeeds.";
        PrototypeProxyEndpointText.Visibility = Visibility.Visible;
        AutomaticRotationToggle.IsEnabled = false;
        NewIdentityButton.IsEnabled = false;
        KillSwitchBoundaryBar.Title = "System kill switch is unavailable";
        KillSwitchBoundaryBar.Message = "Fail-closed applies only to requests made through the local proxy; this build has no WFP or Wintun protection.";
        KillSwitchPolicyText.Text = "Application-scoped proxy closes on route failure";
#endif
        daemon.StateChanged += (_, state) =>
            DispatcherQueue.TryEnqueue(() => ApplyState(state));
        daemon.ConnectionChanged += (_, connected) =>
            DispatcherQueue.TryEnqueue(() => ApplyDaemonConnection(connected));
        Navigation.SelectedItem = HomeNavigationItem;
        NavigateTo("home");
        Closed += (_, _) =>
        {
            // Stop reconnecting only. Never send Disconnect when the window exits.
            lifetime.Cancel();
            daemon.Dispose();
        };
        _ = daemon.RunReconnectLoopAsync(lifetime.Token);
    }

    private void Navigation_SelectionChanged(
        NavigationView sender,
        NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItemContainer?.Tag is string tag)
            NavigateTo(tag);
    }

    private void NavigateTo(string tag)
    {
        var destination = tag switch
        {
            "country" => CountryPage,
            "anonymity" => AnonymityPage,
            "route" => RoutePage,
            "rotation" => RotationPage,
            "split" => SplitPage,
            "killswitch" => KillSwitchPage,
            "diagnostics" => DiagnosticsPage,
            "subscription" => SubscriptionPage,
            "settings" => SettingsPage,
            _ => HomePage,
        };

        foreach (var page in new[]
                 {
                     HomePage, CountryPage, AnonymityPage, RoutePage, RotationPage,
                     SplitPage, KillSwitchPage, DiagnosticsPage, SubscriptionPage, SettingsPage,
                 })
        {
            page.Visibility = ReferenceEquals(page, destination)
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        destination.ChangeView(null, 0, null, true);
    }

    private async void ConnectButton_Click(object sender, RoutedEventArgs args)
    {
        await TryDaemonActionAsync(
            () => daemon.SendAcceptedCommandAsync(
                new Request { Connect = new ConnectRequest() }, lifetime.Token),
            "Requesting a protected route…");
    }

    private async void DisconnectButton_Click(object sender, RoutedEventArgs args)
    {
        if (!await ConfirmAsync(
                "Disconnect?",
                "The protected route will stop. Choose keep blocked unless you explicitly need normal networking."))
            return;
        await TryDaemonActionAsync(
            () => daemon.SendAcceptedCommandAsync(
                new Request { Disconnect = new DisconnectRequest { KeepKillSwitch = true } },
                lifetime.Token),
            "Requesting tunnel shutdown while keeping traffic blocked…");
    }

    private async void NewIdentityButton_Click(object sender, RoutedEventArgs args)
    {
        if (!await ConfirmAsync(
                "Create a new identity?",
                "Hard rotation closes active connections and clears transient DNS and gateway state."))
            return;
        await TryDaemonActionAsync(
            () => daemon.SendConfirmedCommandAsync(
                new Request { Rotate = new RotateRequest { Kind = RotationKind.HardNewIdentity } },
                CriticalAction.HardRotation,
                lifetime.Token),
            "Requesting a new identity…");
    }

    private async Task TryDaemonActionAsync(Func<Task> action, string pendingMessage)
    {
        StatusText.Text = pendingMessage;
        StatusDetailText.Text = "Waiting for an authenticated response from the protection service.";
        ServiceStatusBar.IsOpen = false;

        try
        {
            await action();
            // The authenticated daemon state event is the only authority for
            // the visible lifecycle. Do not overwrite it with an optimistic UI state.
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
        {
            // Window shutdown cancels outstanding UI work without changing tunnel state.
        }
        catch
        {
            StatusText.Text = "Protection service unavailable";
            StatusDetailText.Text = "The request was not sent. Protection state remains unknown and must be treated as blocked.";
            ServiceStatusBar.Title = "Control request was not sent";
#if ONIONROUTE_LOCAL_PROTOTYPE
            ServiceStatusBar.Message = "Start OnionRoute with Start-OnionRoute-Prototype.cmd so the local Tor backend and daemon are available.";
#else
            ServiceStatusBar.Message = "Install and start the signed Windows protection service before using tunnel controls.";
#endif
            ServiceStatusBar.Severity = InfoBarSeverity.Error;
            ServiceStatusBar.IsOpen = true;
        }
    }

    private void ApplyDaemonConnection(bool connected)
    {
        if (connected)
        {
            ServiceStatusBar.IsOpen = false;
            return;
        }

        StatusText.Text = "Local protection daemon unavailable";
        StatusDetailText.Text = "No authenticated state is available. The application-scoped route must be treated as stopped.";
        ServiceStatusBar.Title = "Protection daemon disconnected";
        ServiceStatusBar.Message = "The client is retrying the authenticated local control channel.";
        ServiceStatusBar.Severity = InfoBarSeverity.Error;
        ServiceStatusBar.IsOpen = true;
        ConnectButton.IsEnabled = false;
        DisconnectButton.IsEnabled = false;
        NewIdentityButton.IsEnabled = false;
    }

    private void ApplyState(StateSnapshot state)
    {
        ServiceStatusBar.IsOpen = false;
        StatusText.Text = state.Phase switch
        {
            TunnelPhase.Disconnected => "Direct Tor route stopped",
            TunnelPhase.Preparing => "Preparing local route",
            TunnelPhase.KillSwitchEngaged => "Application route guard ready",
            TunnelPhase.BootstrappingTor => "Bootstrapping Tor",
            TunnelPhase.ConnectingGateway => "Verifying onion route",
            TunnelPhase.Connected => "Direct Tor proxy ready",
            TunnelPhase.Rotating => "Changing Tor identity",
            TunnelPhase.Degraded => "Tor route degraded",
            TunnelPhase.Blocked => "Route blocked — no proxy fallback",
            TunnelPhase.Disconnecting => "Stopping local route",
            TunnelPhase.FatalError => "Protection daemon error",
            _ => "State unknown — fail closed",
        };
        StatusDetailText.Text = state.Phase switch
        {
            TunnelPhase.Connected => "The daemon verified the configured Tor route. Only applications explicitly using the local proxy are covered.",
            TunnelPhase.Blocked => "The protected proxy route is unavailable; requests through it are rejected instead of sent directly.",
            TunnelPhase.Disconnected => "The local proxy is stopped. Other Windows traffic was never captured by this prototype.",
            TunnelPhase.BootstrappingTor => $"Tor bootstrap is {state.TorBootstrapPercent}% complete.",
            _ => "State reported by the authenticated local daemon.",
        };

        ExitCountryValue.Text = string.IsNullOrWhiteSpace(state.ExitCountryCode)
            ? "Not selected"
            : state.ExitCountryCode.ToUpperInvariant();
        AnonymityModeValue.Text = state.AnonymityMode switch
        {
            AnonymityMode.DirectTor => "Direct Tor",
            AnonymityMode.Standard => "Standard",
            AnonymityMode.Enhanced => "Enhanced",
            AnonymityMode.Maximum => "Maximum",
            _ => "Unavailable",
        };
        TorBootstrapProgress.Value = Math.Clamp(state.TorBootstrapPercent, 0u, 100u);
        GatewayValue.Text = $"{FormatGateway(state.GatewayStatus)} / {FormatLatency(state.LatencyBucket)}";
#if ONIONROUTE_LOCAL_PROTOTYPE
        KillSwitchValue.Text = state.Phase == TunnelPhase.Blocked
            ? "Proxy closed (app-scoped)"
            : "Not system-wide";
        BlockedLeaksValue.Text = state.BlockedLeakCount == 0
            ? "Not measured system-wide"
            : $"{state.BlockedLeakCount} proxy request(s)";
        UdpValue.Text = "Unsupported by local proxy";
#else
        KillSwitchValue.Text = state.KillSwitch.ToString();
        BlockedLeaksValue.Text = state.BlockedLeakCount.ToString();
        UdpValue.Text = state.UdpBlocked ? "Blocked by policy" : "Unverified";
#endif

        var active = state.Phase is not TunnelPhase.Disconnected
            and not TunnelPhase.Blocked
            and not TunnelPhase.FatalError;
        ConnectButton.IsEnabled = !active;
        DisconnectButton.IsEnabled = active;
#if ONIONROUTE_LOCAL_PROTOTYPE
        NewIdentityButton.IsEnabled = false;
#else
        NewIdentityButton.IsEnabled = state.Phase == TunnelPhase.Connected;
#endif
    }

    private static string FormatGateway(GatewayStatus value) => value switch
    {
        GatewayStatus.NotApplicable => "Direct Tor",
        GatewayStatus.Connecting => "Connecting",
        GatewayStatus.Healthy => "Healthy",
        GatewayStatus.Degraded => "Degraded",
        GatewayStatus.Unreachable => "Unreachable",
        _ => "Unavailable",
    };

    private static string FormatLatency(LatencyBucket value) => value switch
    {
        LatencyBucket.Low => "low latency",
        LatencyBucket.Medium => "medium latency",
        LatencyBucket.High => "high latency",
        LatencyBucket.VeryHigh => "very high latency",
        _ => "latency unavailable",
    };

    private async Task<bool> ConfirmAsync(string title, string body)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            Title = title,
            Content = body,
            PrimaryButtonText = "Confirm",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }
}
