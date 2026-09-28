SHELL := /bin/bash
VERSION := $(shell cargo metadata --no-deps --format-version 1 | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -n1)

.PHONY: help build test lint fmt package package-deb package-rpm package-arch package-universal package-all clean release

help:
	@echo "make build            cargo build --release"
	@echo "make test             cargo test --workspace"
	@echo "make lint             clippy + fmt --check"
	@echo "make package-universal  static musl tarball (no container)"
	@echo "make package-deb      Debian 12 + Ubuntu 22.04 .deb (podman)"
	@echo "make package-rpm      Rocky 8 .rpm (podman)"
	@echo "make package-arch     Arch .pkg.tar.zst (podman)"
	@echo "make package-all      all of the above"
	@echo "make release VERSION=x.y.z  bump version, tag and push"

build:
	cargo build --release --locked -p okagent

test:
	cargo test --workspace

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

package-universal:
	bash packaging/universal/build.sh

package-deb:
	bash packaging/build-packages.sh deb

package-rpm:
	bash packaging/build-packages.sh rpm

package-arch:
	bash packaging/build-packages.sh arch

package-all:
	bash packaging/build-packages.sh all

clean:
	cargo clean
	rm -rf dist

release:
	@test -n "$(VERSION)" || (echo "usage: make release VERSION=x.y.z" && exit 1)
	bash packaging/release.sh "$(VERSION)"
