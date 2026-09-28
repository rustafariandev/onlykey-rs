#!/usr/bin/env bash
# Bump the workspace version, sync packaging metadata, test, commit and tag.
#
#   packaging/release.sh 0.2.0
#   packaging/release.sh 0.2.0 --push     # also push the commit and tag
#
# Updates Cargo.toml, Cargo.lock, packaging/debian/changelog,
# packaging/arch/PKGBUILD and packaging/rpm/okagent.spec, runs fmt, clippy and
# the tests, commits, and creates an annotated vX.Y.Z tag. Pushing the tag
# triggers .github/workflows/release.yml, which builds every package and
# attaches it to the GitHub release.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

usage="usage: release.sh X.Y.Z [--push]"
version="${1:?$usage}"
push=false
[[ "${2:-}" == "--push" ]] && push=true

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: version must be X.Y.Z, got '$version'" >&2
  exit 1
fi
tag="v$version"

workspace_version() {
  cargo metadata --no-deps --format-version 1 \
    | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -n1
}

current="$(workspace_version)"
if [[ "$current" == "$version" ]]; then
  echo "error: version is already $version" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is dirty; commit or stash first" >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "error: tag $tag already exists" >&2
  exit 1
fi

echo "==> Cargo.toml: $current -> $version"
sed -i -E "s/^version = \"$current\"$/version = \"$version\"/" Cargo.toml
# The internal path dependency pins the library version explicitly.
sed -i -E "s/(onlykey-agent = \{ path = \"\.\.\", version = )\"$current\"/\1\"$version\"/" \
  okagent/Cargo.toml

echo "==> Cargo.lock"
cargo update --workspace --quiet

echo "==> packaging/debian/changelog"
deb_date="$(date -R)"
{
  printf 'okagent (%s-1) unstable; urgency=medium\n\n' "$version"
  printf '  * New upstream release %s.\n\n' "$tag"
  printf ' -- Rustafarian Dev <rustafarian.dev@gmail.com>  %s\n\n' "$deb_date"
  cat packaging/debian/changelog
} > packaging/debian/changelog.new
mv packaging/debian/changelog.new packaging/debian/changelog

echo "==> packaging/arch/PKGBUILD"
sed -i -E "s/^pkgver=.*/pkgver=$version/" packaging/arch/PKGBUILD
sed -i -E "s/^pkgrel=.*/pkgrel=1/" packaging/arch/PKGBUILD

echo "==> packaging/rpm/okagent.spec"
sed -i -E "s/^Version:.*/Version:        $version/" packaging/rpm/okagent.spec
spec_date="$(LC_ALL=C date '+%a %b %d %Y')"
{
  sed "s|^%changelog$|%changelog\n* $spec_date Rustafarian Dev <rustafarian.dev@gmail.com> - $version-1\n- New upstream release $tag.|" \
    packaging/rpm/okagent.spec
} > packaging/rpm/okagent.spec.new
mv packaging/rpm/okagent.spec.new packaging/rpm/okagent.spec

echo "==> verifying"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

echo "==> committing"
git add Cargo.toml Cargo.lock okagent/Cargo.toml packaging/debian/changelog \
  packaging/arch/PKGBUILD packaging/rpm/okagent.spec
git commit -m "Release $tag"
git tag -a "$tag" -m "okagent $version"

if $push; then
  echo "==> pushing"
  git push origin HEAD --follow-tags
  echo "Pushed $tag; the release workflow will build the packages."
else
  echo
  echo "Tagged $tag. Publish with:"
  echo "  git push origin HEAD --follow-tags"
fi
