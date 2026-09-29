%global commit 0
%global giturl https://github.com/rustafariandev/onlykey-rs.git

%if 0%{?fedora} || 0%{?rhel} >= 9
%global userunitdir %{_usr}/lib/systemd/user
%global udevrulesdir %{_usr}/lib/udev/rules.d
%else
%global userunitdir %{_datadir}/systemd/user
%global udevrulesdir %{_sysconfdir}/udev/rules.d
%endif

%if 0%{?rhel}
%global completiondir %{_datadir}/bash-completion/completions
%else
%global completiondir %{_datadir}/bash-completion/completions
%endif

Name:           okagent
Version:        1.0.0
Release:        1%{?dist}
Summary:        SSH agent backed by an OnlyKey hardware token
License:        MIT
URL:            https://github.com/rustafariandev/onlykey-rs
Source0:        %{name}-%{version}.tar.gz
# The binary is not stripped by us and there is no separate debug source
# tree to split out; skip the debuginfo subpackages entirely.
%global debug_package %{nil}
BuildRequires:  gcc
BuildRequires:  glibc-devel
Requires:       glibc
Recommends:     libnotify

%description
okagent derives SSH keys on an OnlyKey hardware token from an identity
string, so the private key never leaves the device, and signs with them
after a challenge is entered on the token's buttons. The derivation
matches the Python onlykey-agent, so existing authorized_keys entries keep
working. It supports ed25519 and nistp256 (derived, or stored in an ECC
slot) and RSA 2048/4096 (stored in an RSA slot), and can run as an SSH
agent, wrap ssh and mosh, or serve on a unix socket.

Note: the build needs Rust 1.85 or newer for edition 2024. Distribution
toolchains on RHEL are too old, so the release build installs a pinned
rustup toolchain inside the build environment (see packaging/README.md).

%prep
%autosetup -n onlykey-rs-%{version}

%build
# Prefer a modern toolchain when one is present (the release/CI build
# installs rustup); fall back to a distribution cargo otherwise.
if [ -x /usr/local/cargo/bin/cargo ]; then
  export PATH="/usr/local/cargo/bin:$PATH"
fi
cargo build --release --locked -p okagent
mkdir -p completions
target/release/okagent completions bash > completions/okagent.bash
target/release/okagent completions zsh  > completions/_okagent
target/release/okagent completions fish > completions/okagent.fish

%install
install -Dpm 0755 target/release/okagent %{buildroot}%{_bindir}/okagent
install -Dpm 0644 okagent/okagent.1 %{buildroot}%{_mandir}/man1/okagent.1
install -Dpm 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -Dpm 0644 LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE
install -Dpm 0644 packaging/common/okagent.service \
  %{buildroot}%{userunitdir}/okagent.service
install -Dpm 0644 packaging/common/49-onlykey.rules \
  %{buildroot}%{udevrulesdir}/49-onlykey.rules
install -Dpm 0644 completions/okagent.bash \
  %{buildroot}%{completiondir}/okagent
install -Dpm 0644 completions/_okagent \
  %{buildroot}%{_datadir}/zsh/site-functions/_okagent
install -Dpm 0644 completions/okagent.fish \
  %{buildroot}%{_datadir}/fish/vendor_completions.d/okagent.fish

%files
%license %{_licensedir}/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%{_bindir}/okagent
%{_mandir}/man1/okagent.1*
%{userunitdir}/okagent.service
%{udevrulesdir}/49-onlykey.rules
%{completiondir}/okagent
%{_datadir}/zsh/site-functions/_okagent
%{_datadir}/fish/vendor_completions.d/okagent.fish

%post
if [ -x /usr/bin/udevadm ]; then
  /usr/bin/udevadm control --reload-rules >/dev/null 2>&1 || :
  /usr/bin/udevadm trigger >/dev/null 2>&1 || :
fi

%postun
if [ -x /usr/bin/udevadm ] && [ "$1" -eq 0 ]; then
  /usr/bin/udevadm control --reload-rules >/dev/null 2>&1 || :
fi

%changelog
* Tue Sep 29 2026 Rustafarian Dev <rustafarian.dev@gmail.com> - 1.0.0-1
- New upstream release v1.0.0.
* Mon Sep 28 2026 Rustafarian Dev <rustafarian.dev@gmail.com> - 0.1.0-1
- Initial package.
