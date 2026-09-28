# Packaging

Packages for RHEL, Debian, Ubuntu, Arch and a universal static binary.

Every package installs the same payload:

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
older, so every source build installs a pinned rustup toolchain inside a
distro-matched container and then builds against that distro's glibc. The
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
make package-all
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
sudo apt install ./okagent_0.1.0-1_amd64.deb

# RHEL / Fedora
sudo dnf install ./okagent-0.1.0-1.el8.x86_64.rpm

# Arch
sudo pacman -U okagent-0.1.0-1-x86_64.pkg.tar.zst

# Universal static binary
tar xzf okagent-0.1.0-x86_64-unknown-linux-musl.tar.gz
sudo ./okagent-0.1.0-x86_64-unknown-linux-musl/install.sh
```

After installing, replug the OnlyKey (the udev rule is picked up on
reconnect), then start the agent:

```sh
systemctl --user enable --now okagent
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/okagent/agent.sock"
ssh-add -L
```

## Releasing

```sh
make release VERSION=0.2.0     # bump, test, commit, tag
git push origin HEAD --follow-tags
```

`packaging/release.sh` syncs the workspace version into `Cargo.toml`,
`Cargo.lock`, `packaging/debian/changelog`, `packaging/arch/PKGBUILD` and
`packaging/rpm/okagent.spec`, then creates the annotated `vX.Y.Z` tag. The
tag triggers `.github/workflows/release.yml`, which builds every artifact on
GitHub runners and attaches them (with `SHA256SUMS`) to the release. CI
(`.github/workflows/ci.yml`) runs fmt, clippy and the tests on Linux and
macOS for every push and pull request.

## Layout

```
packaging/
  common/49-onlykey.rules   upstream udev rule
  common/okagent.service    systemd --user unit
  universal/build.sh        static musl tarball
  debian/                   native Debian/Ubuntu packaging
  rpm/okagent.spec          native RPM spec
  arch/PKGBUILD             Arch build recipe
  build-packages.sh         podman orchestration
  release.sh                version bump + tag
Makefile                    wrappers over the scripts
```

The udev rule is taken from <https://docs.crp.to/linux.html> and shipped
verbatim, including its `MODE:="0666"` line; the comments in the file
describe how to tighten it to an owner or group.
