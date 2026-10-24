# Packaging

Packages for RHEL, Debian, Ubuntu, Arch, a universal static binary, and a
Windows zip ([below](#windows)).

Every Linux package installs the same payload:

| Path | File |
| --- | --- |
| `/usr/bin/okagent` | the agent |
| `/usr/share/man/man1/okagent.1` | man page |
| `/usr/lib/systemd/user/okagent.service` | user unit (shipped, not enabled) |
| `/usr/lib/udev/rules.d/49-onlykey.rules` | udev rule (or `/etc/udev/rules.d` on EL8) |
| `.../bash-completion/completions/okagent` | bash completion |
| `.../zsh/site-functions/_okagent` | zsh completion |
| `.../fish/vendor_completions.d/okagent.fish` | fish completion |

The `onlykey-agent` library is not packaged; depend on it from git:

```toml
onlykey-agent = { git = "https://github.com/rustafariandev/onlykey-rs" }
```

## Toolchains

The crate uses `edition = "2024"` and therefore needs **rustc >= 1.85**. The
toolchains shipped by Debian 12 (1.63), Ubuntu 22.04 (1.75) and RHEL 8/9 are
older, so every source build installs a pinned rustup toolchain (1.98.1;
`RUSTUP_VERSION` overrides it) inside a distro-matched container and then builds against that distro's glibc. The
resulting `Depends`/`Requires` are correct for the target, and the RPM built
on Rocky 8 (glibc 2.28) runs forward on EL9/EL10 and Fedora. The static musl
tarball needs no libc at all.

## Building

Containers use `podman` (`CONTAINER_ENGINE=docker` overrides it). Each
container gets its own build cache under `.container-target/` (gitignored)
that shadows the host `target/`, so a binary built on the host with a newer
glibc is never reused inside an older container.

```sh
make package-universal   # dist/okagent-<v>-x86_64-unknown-linux-musl.tar.gz
make package-deb         # dist/okagent_<v>-1_amd64.deb  (Debian 12 + Ubuntu 22.04)
make package-rpm         # dist/okagent-<v>-1.el8.x86_64.rpm
make package-arch        # dist/okagent-<v>-1-x86_64.pkg.tar.zst
make package-all         # every Linux package
make package-windows     # dist/okagent-<v>-x86_64-pc-windows-msvc.{zip,msi} (on Windows)
```

Or directly:

```sh
packaging/build-packages.sh deb            # both bases
packaging/build-packages.sh deb ubuntu     # one base
packaging/build-packages.sh rpm rocky
packaging/build-packages.sh arch
packaging/build-packages.sh universal
```

Two metadata-driven shortcuts also exist for quick local builds (they need
`cargo-deb` / `cargo-generate-rpm`, and `cargo deb` cannot compute `$auto`
dependencies on a non-Debian host):

```sh
cargo install cargo-deb cargo-generate-rpm
cargo deb -p okagent
cargo generate-rpm -p okagent
```

## Installing

```sh
# Debian / Ubuntu
sudo apt install ./okagent_1.0.0-1_amd64.deb

# RHEL / Fedora
sudo dnf install ./okagent-1.0.0-1.el8.x86_64.rpm

# Arch
sudo pacman -U okagent-1.0.0-1-x86_64.pkg.tar.zst

# Universal static binary
tar xzf okagent-1.0.0-x86_64-unknown-linux-musl.tar.gz
sudo ./okagent-1.0.0-x86_64-unknown-linux-musl/install.sh
```

After installing, replug the OnlyKey (the udev rule is picked up on
reconnect), then start the agent:

```sh
systemctl --user enable --now okagent
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/okagent/agent.sock"
ssh-add -L
```

## Windows

`packaging/windows/build.ps1` builds `okagent.exe` with the C runtime linked
statically, so it needs no Visual C++ redistributable, and zips it with
`install.ps1`, a PowerShell completion script, the README and the license:

```powershell
powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1
powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 -Target aarch64-pc-windows-msvc
```

The second needs the MSVC ARM64 build tools; releases ship `x86_64` only.

`install.ps1` installs for the current user, with no administrator rights:

| What | Where |
| --- | --- |
| `okagent.exe`, `okagent-completion.ps1`, `install.ps1` | `%LOCALAPPDATA%\Programs\okagent` |
| that directory | the user `PATH` |
| `\\.\pipe\okagent-USER` | the user `SSH_AUTH_SOCK` (not with `-NoAuthSock`) |
| `okagent serve --daemon` at logon | `shell:startup\okagent.lnk` (with `-Autostart`) |

Run again from a newer zip, it stops the installed agent, replaces it, and
starts it again if it autostarts. `install.ps1 -Uninstall` undoes everything
but the config in `%APPDATA%\okagent`. `-Prefix DIR` installs elsewhere.

### MSI

`build.ps1 -Msi` also builds `okagent-<v>-x86_64-pc-windows-msvc.msi` from
`packaging/windows/okagent.wxs` with the WiX 5 CLI:

```powershell
dotnet tool install --global wix --version 5.0.2
powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 -Msi
```

The MSI is per-user too and installs what `install.ps1` does, to the same
place, with `-Autostart` on by default. It is installed, upgraded and removed
like any other: double-click it, or

```powershell
msiexec /i okagent-2.0.0-x86_64-pc-windows-msvc.msi              # quiet: add /qn
msiexec /i okagent-2.0.0-x86_64-pc-windows-msvc.msi AUTOSTART=0 AUTHSOCK=0
msiexec /x okagent-2.0.0-x86_64-pc-windows-msvc.msi
```

`AUTOSTART=0` skips the Startup shortcut and starting the agent; `AUTHSOCK=0`
leaves `SSH_AUTH_SOCK` alone. Both are remembered by later upgrades. An
upgrade or uninstall first stops every running `okagent.exe` of the user,
wherever it was started from. Use either the MSI or `install.ps1`, not both:
they share the install directory but do not know about each other.

The executable is not code-signed. Windows marks files from a downloaded zip
as coming from the internet; the installer clears that mark on what it
installs.

## Releasing

```sh
make release VERSION=0.2.0     # bump, test, commit, tag
git push origin HEAD --follow-tags
```

`packaging/release.sh` syncs the workspace version into `Cargo.toml`,
`Cargo.lock`, `packaging/debian/changelog`, `packaging/arch/PKGBUILD` and
`packaging/rpm/okagent.spec`, then creates the annotated `vX.Y.Z` tag. The
tag triggers `.github/workflows/release.yml`, which builds every artifact on
GitHub runners and attaches them (with `SHA256SUMS`) to the release, along
with a signed build-provenance attestation for each file. To check that a
downloaded file was built by that workflow from this repository:

```sh
gh attestation verify okagent-*.tar.gz --repo rustafariandev/onlykey-rs
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy and the tests on Linux,
macOS and Windows for every push and pull request.

## Layout

```
packaging/
  common/49-onlykey.rules   upstream udev rule
  common/okagent.service    systemd --user unit
  universal/build.sh        static musl tarball
  debian/                   native Debian/Ubuntu packaging
  rpm/okagent.spec          native RPM spec
  arch/PKGBUILD             Arch build recipe
  windows/build.ps1         Windows zip
  windows/install.ps1       per-user installer shipped in the zip
  windows/okagent.wxs       WiX source for the MSI
  build-packages.sh         podman orchestration
  release.sh                version bump + tag
Makefile                    wrappers over the scripts
```

The udev rule is taken from <https://docs.crp.to/linux.html>, with its
`MODE:="0666"` (read and write for every local user) replaced by
`TAG+="uaccess"`, which grants the device to the user at the active local
session only. The comments in the file describe how to grant it to an owner
or group instead, for machines without a local session.
