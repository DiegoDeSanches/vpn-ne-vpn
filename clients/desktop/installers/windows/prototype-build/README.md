# Reproducible Windows GNU daemon cross-build

This **EXPERIMENTAL build-time helper** cross-compiles the Rust desktop daemon
inside a Linux container. It does not install anything, alter Windows routing,
download components at application runtime, or package Tor/Wintun.

## Requirements

- Docker Desktop running Linux containers.
- The repository is available to Docker Desktop file sharing.
- `clients/desktop/crates/daemon` exposes a binary target named
  `onionroute-desktop-daemon`.
- `clients/desktop/Cargo.lock` is current. Cargo runs with `--locked` and fails
  instead of changing it.

The image pins the currently approved `rust:1.78-bookworm` image digest, installs
only the MinGW-w64 x86-64 GCC cross-toolchain requested by the Windows GNU
target, and installs `x86_64-pc-windows-gnu` through rustup. Docker is fixed to
the `linux/amd64` build platform even on ARM hosts. Dependency downloads happen
only while building the development artifact.

## Build

From the repository root in PowerShell:

```powershell
.\clients\desktop\installers\windows\prototype-build\build-daemon.ps1 `
    -OutputDirectory .\artifacts\prototype-daemon
```

Outputs:

- `onionroute-desktop-daemon.exe`
- `onionroute-desktop-daemon.exe.sha256`

The repository is mounted read-only at `/workspace`. Cargo output remains in an
ephemeral container directory. The container copies one staging file to the
requested directory, then PowerShell atomically replaces the final executable
on the Windows host to avoid stale Docker Desktop bind-mount contents. A
container/host SHA-256 comparison protects that hand-off.

If local execution policy blocks reviewed repository scripts, invoke it in a
one-shot process after inspecting the file:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
    .\clients\desktop\installers\windows\prototype-build\build-daemon.ps1 `
    -OutputDirectory .\artifacts\prototype-daemon
```

## Reproducibility boundary

- Rust is fixed to the 1.78 release line and the target is fixed to
  `x86_64-pc-windows-gnu`.
- Rust dependencies are fixed by the committed desktop `Cargo.lock`.
- The helper directory is the complete Docker build context, so source and local
  artifacts are not copied into the image.
- Release signing, Authenticode identity, installer creation, C Tor, Wintun and
  WFP verification remain separate gates.

Debian package repositories are not immutable release provenance. Before
treating the result as a release artifact, use an approved Debian snapshot and
archive an SBOM/toolchain manifest. This helper is intended only for the current
reproducible development prototype.

## Fail-fast behavior

The PowerShell wrapper stops when Docker is absent/unavailable, repository paths
are wrong, the output is not writable, image build fails, Cargo has no matching
binary target, the lock file would change, or the expected EXE is missing/empty.
The container independently verifies Rust 1.78, the Windows target, the linker,
mounts and output before compiling.
