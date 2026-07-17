using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace OnionRoute.App;

internal static class WindowsPeerVerifier
{
    // The installer writes the reviewed publisher thumbprint at build time.
    private const string ExpectedPublisherThumbprint = "REPLACE_AT_SIGNED_BUILD";

    public static void VerifyDaemon(SafePipeHandle pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe, out var pipePid))
            throw new Win32Exception(Marshal.GetLastWin32Error());
#if ONIONROUTE_LOCAL_PROTOTYPE
        // EXPERIMENTAL: this explicit build uses a same-user console daemon
        // shipped beside the UI, not an installed privileged Windows service.
        if (pipePid == 0)
            throw new UnauthorizedAccessException("Named Pipe server has no process identity");
        VerifyExpectedImage(pipePid, Path.Combine(
            AppContext.BaseDirectory, "onionroute-desktop-daemon.exe"));
#else
        var servicePid = ServiceIdentity.QueryProcessId("OnionRoute");
        if (pipePid == 0 || pipePid != servicePid)
            throw new UnauthorizedAccessException("Named Pipe server is not the OnionRoute service");
        VerifyExpectedImage(pipePid, Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "OnionRoute", "onionroute-desktop-daemon.exe"));
        // EXPERIMENTAL: production build must call WinVerifyTrust and compare the
        // validated signer certificate to ExpectedPublisherThumbprint.
        if (ExpectedPublisherThumbprint == "REPLACE_AT_SIGNED_BUILD")
            throw new UnauthorizedAccessException("Unsigned development peer identity is disabled");
#endif
    }

    private static void VerifyExpectedImage(uint processId, string expectedPath)
    {
        using var process = Process.GetProcessById(checked((int)processId));
        var actualPath = process.MainModule?.FileName ?? throw new UnauthorizedAccessException();
        if (!string.Equals(
                Path.GetFullPath(actualPath),
                Path.GetFullPath(expectedPath),
                StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Unexpected protection daemon image path");
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);
}

internal static class ServiceIdentity
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;

    public static uint QueryProcessId(string serviceName)
    {
        var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var service = OpenService(manager, serviceName, ServiceQueryStatus);
            if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                var size = Marshal.SizeOf<SERVICE_STATUS_PROCESS>();
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (!QueryServiceStatusEx(service, ScStatusProcessInfo, buffer, size, out _))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    return Marshal.PtrToStructure<SERVICE_STATUS_PROCESS>(buffer).ProcessId;
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode,
            ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, ServiceFlags;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int level, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
