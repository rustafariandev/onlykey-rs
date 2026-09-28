#!/usr/bin/env bash
# Build okagent packages locally with podman.
#
#   packaging/build-packages.sh deb        # Debian 12 and Ubuntu 22.04 .deb
#   packaging/build-packages.sh deb debian # one base image only
#   packaging/build-packages.sh rpm        # Rocky 8 .rpm (also runs on EL9/10)
#   packaging/build-packages.sh arch       # Arch .pkg.tar.zst
#   packaging/build-packages.sh universal  # static musl tarball (host, no container)
#   packaging/build-packages.sh all
#
# Packages are built from source in a distro-matched container, so the
# recorded glibc dependency matches the target. Because edition 2024 needs
# rustc >= 1.85 and the distro toolchains are older, each container installs
# a pinned rustup toolchain before building.
#
# The container scripts below are single-quoted; the unquoted "$rustup_version"
# fragments are spliced in by this outer shell on purpose (SC2016).
# shellcheck disable=SC2016
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
dist="$root/dist"
engine="${CONTAINER_ENGINE:-podman}"
rustup_version="${RUSTUP_VERSION:-stable}"

mkdir -p "$dist"

die() { echo "error: $*" >&2; exit 1; }

require_engine() {
  command -v "$engine" >/dev/null 2>&1 || die "$engine is not installed"
}

# Runs a command as root inside an image, with the repo bind-mounted.
# $1 image, $2 cache key (per-container target dir), rest: shell command.
# The host `target/` is shadowed by a container-specific empty directory so
# that a binary built on the host (with a newer glibc) is never reused inside
# the container; each image gets its own cache.
in_container() {
  local image="$1" key="$2"; shift 2
  local cache="$root/.container-target/$key"
  mkdir -p "$cache"
  "$engine" run --rm \
    -v "$root:/work:Z" \
    -v "$cache:/work/target:Z" \
    -w /work \
    "$image" /bin/sh -euxc "$*"
}

install_rustup() {
  # $1 = toolchain, tested on Debian/Ubuntu (curl) and EL (curl-minimal).
  local tc="$1"
  if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain "$tc"
  fi
  export PATH="$HOME/.cargo/bin:$PATH"
}

build_deb() {
  local image="$1" tag="$2"
  echo "==> $tag ($image)"
  in_container "$image" "${image//[:\/]/_}" '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      build-essential curl ca-certificates pkg-config \
      debhelper devscripts dpkg-dev fakeroot
    if ! command -v cargo >/dev/null 2>&1; then
      curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain '"$rustup_version"'
    fi
    export PATH="$HOME/.cargo/bin:$PATH"
    rm -rf debian completions
    cp -r packaging/debian debian
    dpkg-buildpackage -us -uc -b
    mv ../okagent_*.deb /work/dist/
    rm -rf debian completions
  '
}

build_rpm() {
  local image="$1" tag="$2"
  echo "==> $tag ($image)"
  in_container "$image" "${image//[:\/]/_}" '
    dnf install -y -q rpm-build gcc make ca-certificates git tar || \
      dnf install -y -q --allowerasing rpm-build gcc make ca-certificates git tar
    command -v curl >/dev/null 2>&1 || dnf install -y -q curl-minimal
    if ! command -v cargo >/dev/null 2>&1; then
      curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain '"$rustup_version"'
    fi
    export PATH="$HOME/.cargo/bin:$PATH"
    version="$(cargo metadata --no-deps --format-version 1 \
      | sed -n "s/.*\"version\":\"\([^\"]*\)\".*/\1/p" | head -n1)"
    mkdir -p "$HOME/rpmbuild/SOURCES"
    tar --transform "s,^,onlykey-rs-$version/," \
      --exclude=.git --exclude=target --exclude=dist \
      -czf "$HOME/rpmbuild/SOURCES/okagent-$version.tar.gz" .
    rpmbuild -bb packaging/rpm/okagent.spec \
      --define "_topdir $HOME/rpmbuild" \
      --define "_sourcedir $HOME/rpmbuild/SOURCES"
    find "$HOME/rpmbuild/RPMS" -name "*.rpm" -exec cp {} /work/dist/ \;
  '
}

build_arch() {
  echo "==> Arch (archlinux:latest)"
  in_container archlinux:latest arch '
    pacman -Sy --noconfirm --needed base-devel rustup git
    rustup default '"$rustup_version"'
    useradd -m builder
    version="$(cargo metadata --no-deps --format-version 1 \
      | sed -n "s/.*\"version\":\"\([^\"]*\)\".*/\1/p" | head -n1)"
    # Stage the working tree as the source tarball makepkg expects, so local
    # builds do not need a pushed vX.Y.Z tag. Everything writable lives in the
    # builder scratch dir; the bind-mounted repo is only read.
    machinedir=/home/builder/pkg
    srcdest="$machinedir/srcdest"
    mkdir -p "$srcdest"
    tar --transform "s,^,onlykey-rs-$version/," \
      --exclude=.git --exclude=target --exclude=dist \
      -czf "$srcdest/okagent-$version.tar.gz" .
    cp packaging/arch/PKGBUILD packaging/arch/okagent.install "$machinedir/"
    chown -R builder:builder "$machinedir"
    su builder -c "cd $machinedir && SRCDEST=$srcdest makepkg -f --noconfirm"
    mv "$machinedir"/okagent-*.pkg.tar.zst /work/dist/
  '
}

case "${1:-all}" in
  universal)
    bash packaging/universal/build.sh
    ;;
  deb)
    require_engine
    case "${2:-all}" in
      debian) build_deb "debian:12" "Debian 12" ;;
      ubuntu) build_deb "ubuntu:22.04" "Ubuntu 22.04" ;;
      all)    build_deb "debian:12" "Debian 12"; build_deb "ubuntu:22.04" "Ubuntu 22.04" ;;
      *) die "unknown deb base: $2 (debian|ubuntu|all)" ;;
    esac
    ;;
  rpm)
    require_engine
    case "${2:-all}" in
      rocky)  build_rpm "rockylinux:8" "Rocky 8" ;;
      rocky9) build_rpm "rockylinux:9" "Rocky 9" ;;
      fedora) build_rpm "fedora:latest" "Fedora" ;;
      all)    build_rpm "rockylinux:8" "Rocky 8" ;;
      *) die "unknown rpm base: $2 (rocky|rocky9|fedora|all)" ;;
    esac
    ;;
  arch)
    require_engine
    build_arch
    ;;
  rpm-tool)
    require_engine
    echo "==> cargo-generate-rpm"
    in_container "rockylinux:8" rpm-tool '
      dnf install -y -q gcc make curl ca-certificates
      if ! command -v cargo >/dev/null 2>&1; then
        curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
          | sh -s -- -y --profile minimal --default-toolchain '"$rustup_version"'
      fi
      export PATH="$HOME/.cargo/bin:$PATH"
      cargo install cargo-generate-rpm --locked || true
      cargo build --release --locked -p okagent
      mkdir -p target/completions
      target/release/okagent completions bash > target/completions/okagent.bash
      target/release/okagent completions zsh  > target/completions/_okagent
      target/release/okagent completions fish > target/completions/okagent.fish
      cargo generate-rpm -p okagent -o /work/dist/
    '
    ;;
  all)
    require_engine
    bash packaging/universal/build.sh
    build_deb "debian:12" "Debian 12"
    build_deb "ubuntu:22.04" "Ubuntu 22.04"
    build_rpm "rockylinux:8" "Rocky 8"
    build_arch
    ;;
  *)
    die "usage: $0 {all|universal|deb [debian|ubuntu]|rpm [rocky|rocky9|fedora]|arch|rpm-tool}"
    ;;
esac

echo
echo "artifacts in $dist:"
ls -la "$dist"
