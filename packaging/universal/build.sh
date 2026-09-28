#!/usr/bin/env bash
# Build the universal static binary tarball for Linux (x86_64).
#
# Uses the musl target so the result runs on any Linux distribution,
# regardless of its glibc: `hidapi`'s `linux-native-basic-udev` backend is
# pure Rust and reads /dev/hidraw* directly, so nothing is linked against
# libc beyond the static musl.
#
# Output: dist/okagent-<version>-x86_64-unknown-linux-musl.tar.gz
#         and an appended SHA256SUMS.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

target="${TARGET:-x86_64-unknown-linux-musl}"
version="$(cargo metadata --no-deps --format-version 1 \
  | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -n1)"
name="okagent-${version}-${target}"
dist="$root/dist"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

if ! rustup target list --installed | grep -qx "$target"; then
  echo "installing rustup target $target" >&2
  rustup target add "$target"
fi

echo "building okagent $version for $target" >&2
cargo build --release --locked -p okagent --target "$target"

prefix="$stage/$name"
mkdir -p "$prefix/bin" "$prefix/share/man/man1" \
  "$prefix/share/bash-completion/completions" \
  "$prefix/share/zsh/site-functions" \
  "$prefix/share/fish/vendor_completions.d" \
  "$prefix/share/systemd/user" \
  "$prefix/share/doc/okagent" \
  "$prefix/share/udev/rules.d"

install -m 0755 "target/$target/release/okagent" "$prefix/bin/okagent"
install -m 0644 okagent/okagent.1 "$prefix/share/man/man1/okagent.1"
install -m 0644 packaging/common/49-onlykey.rules "$prefix/share/udev/rules.d/49-onlykey.rules"
install -m 0644 packaging/common/okagent.service "$prefix/share/systemd/user/okagent.service"
install -m 0644 README.md LICENSE "$prefix/share/doc/okagent/"

"$prefix/bin/okagent" completions bash > "$prefix/share/bash-completion/completions/okagent"
"$prefix/bin/okagent" completions zsh  > "$prefix/share/zsh/site-functions/_okagent"
"$prefix/bin/okagent" completions fish > "$prefix/share/fish/vendor_completions.d/okagent.fish"

cat > "$prefix/install.sh" <<'EOF'
#!/bin/sh
# Install okagent into $PREFIX (default /usr/local).
set -eu
PREFIX="${PREFIX:-/usr/local}"
here="$(cd -- "$(dirname -- "$0")" && pwd)"
install -Dm0755 "$here/bin/okagent" "$PREFIX/bin/okagent"
install -Dm0644 "$here/share/man/man1/okagent.1" "$PREFIX/share/man/man1/okagent.1"
install -Dm0644 "$here/share/bash-completion/completions/okagent" "$PREFIX/share/bash-completion/completions/okagent"
install -Dm0644 "$here/share/zsh/site-functions/_okagent" "$PREFIX/share/zsh/site-functions/_okagent"
install -Dm0644 "$here/share/fish/vendor_completions.d/okagent.fish" "$PREFIX/share/fish/vendor_completions.d/okagent.fish"
echo "installed okagent to $PREFIX/bin/okagent"
echo "For non-root USB access, copy 49-onlykey.rules to /etc/udev/rules.d/ and run:"
echo "  sudo udevadm control --reload-rules && sudo udevadm trigger"
EOF
chmod 0755 "$prefix/install.sh"

mkdir -p "$dist"
tar -C "$stage" -czf "$dist/$name.tar.gz" "$name"
( cd "$dist" && sha256sum "$name.tar.gz" >> SHA256SUMS )
echo "wrote $dist/$name.tar.gz" >&2
