# Windows installer prototype

WiX installs an automatic LocalSystem Windows Service, the unprivileged WinUI
shell and a pinned upstream-signed `wintun.dll`. The service validates the DLL
signature/hash, creates/removes the Wintun adapter, installs persistent WFP
filters and stores recovery intent with machine-scope DPAPI plus a service-only
ACL. Named Pipe SDDL allows SYSTEM full access and only the owning interactive
user read/write after service enrollment.

Rollback intentionally keeps the emergency WFP block if platform enrollment was
partially applied. A repair/uninstall flow must first prove that TUN/core teardown
completed, then remove filters and driver artifacts. Release signing must patch
the same publisher thumbprint into the WinUI peer verifier. Clean-VM tests must
cover install, upgrade, rollback, forced reboot, service crash and uninstall.

