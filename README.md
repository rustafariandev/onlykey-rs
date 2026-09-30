# onlykey-rs

SSH keys on an [OnlyKey](https://onlykey.io) hardware token, from Rust.

A clean-room port of the SSH half of the Python
[`onlykey-agent`](https://github.com/trustcrypto/onlykey-agent). The private
key never leaves the token: it is re-derived on the device from an identity
string such as `ferris@example.com` for every operation, and each signature is
confirmed by entering a 3-digit challenge on the buttons. Given the same
identity and curve this port derives exactly the same public key as the
Python agent, so existing `authorized_keys` entries keep working. Keys the
OnlyKey app has written into one of the token's 16 ECC slots or 4 RSA slots
("stored keys") can be used the same way.

Two crates:

- **`okagent`**: a command-line SSH agent.
- **`onlykey-agent`**: the library underneath it.

Scope: SSH only (no GPG, no age), the original OnlyKey (not DUO), Linux and macOS.
Key types: ed25519 and nistp256 (derived or stored), RSA 2048 and 4096
(stored only). A plain ed25519, RSA, ECDSA (nistp256/384/521) or DSA private
key can also be loaded into a running agent with `ssh-add FILE` and signed in
memory, with no token involved. FIDO security-key SSH keys
(`sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`) can be
loaded the same way and are signed by the attached authenticator over a
pure-Rust CTAP2 client, with no C library involved.

## Setup

- A Rust toolchain (edition 2024).
- Linux: no C libraries, the HID backend is pure Rust and reads
  `/dev/hidraw*` directly. A udev rule is needed so the device can be opened
  without root: copy `49-onlykey.rules` from the
  [OnlyKey docs](https://docs.crp.to/linux.html) to `/etc/udev/rules.d/` and
  replug the device. "Permission denied" means the rule is missing.
- macOS: the Xcode Command Line Tools (`xcode-select --install`), which
  build hidapi's IOKit backend. No driver or permission setup is needed.

```sh
cargo install --git https://github.com/rustafariandev/onlykey-rs okagent
```

Prebuilt packages and a static binary are published on the
[releases page](https://github.com/rustafariandev/onlykey-rs/releases): a
universal `x86_64` musl tarball, a `.deb` for Debian 12+ and Ubuntu 22.04+,
an `.rpm` for RHEL 8+, and a `.pkg.tar.zst` for Arch. Each installs the
binary, man page, a systemd user unit, the udev rule, and shell completions;
see [`packaging/README.md`](packaging/README.md). `okagent completions SHELL`
prints a completion script, and `make package-all` builds every package
locally with podman.

A man page lives at `okagent/okagent.1`; `man -l okagent/okagent.1` reads it
from the checkout, or copy it to `~/.local/share/man/man1/` to get
`man okagent`.

## okagent

| Command | What it does |
| --- | --- |
| `okagent status` | Firmware version and lock state of the attached token. |
| `okagent pubkey ID...` | Public keys in `authorized_keys` format. |
| `okagent run ID... -- CMD` | Run a command with a temporary agent in `SSH_AUTH_SOCK` (and `SSH_AGENT_PID`). |
| `okagent shell ID...` | Start `$SHELL` with a temporary agent. |
| `okagent ssh ID [ARGS]` | Connect with ssh; the host part of the identity is the destination, and a `:port` suffix is passed as `-p`. `--host` overrides the destination; `-i ID` serves extra keys for forwarding. |
| `okagent mosh ID [ARGS]` | The same with mosh; its ssh step uses the identity's key. `--host` overrides the destination, and `-i` serves extra keys. |
| `okagent ssh-copy-id ID [ARGS]` | Install the identity's public key on the host with ssh-copy-id. `--host` overrides the destination. |
| `okagent serve [ID...]` | Long-lived agent on a unix socket. |

An identity is `[user@]host`. Pass `--curve nistp256` for a P-256 key; the
default is ed25519. Identities can be omitted when the config file lists them,
or when `--pubkey-file` names them (see below).

By default the identity's host is also the ssh destination. Pass
`--host [user@]server[:port]` to `ssh`, `mosh` or `ssh-copy-id` to connect
somewhere else while the identity still names the key. So
`okagent ssh ferris@example.com --host admin@server.example.com` signs as
`ferris@example.com` but logs in as `admin` on `server.example.com`. A
`--host` without a user keeps the identity's user; a `--host` without a port
uses the default port (the identity's `:port` is not carried over).

Pass `--slot ECC3` (slots `ECC1` to `ECC16`) or `--slot RSA1` (`RSA1` to
`RSA4`) to use the key stored in that slot instead of deriving one. The
identity then only names the key: it appears in the prompt and the key
comment, and `okagent ssh` still takes the destination from it. For an ECC
slot the curve must match the key type the slot was written with; a mismatch
is reported as such rather than producing a wrong key. An RSA slot takes no
curve, and whether it holds a 2048- or 4096-bit key is read from the token.
RSA keys are never derived, only stored. The token signs SHA-256 or SHA-512
digests, so a client asking for the legacy SHA-1 `ssh-rsa` signature is
refused; OpenSSH has asked for `rsa-sha2-*` since 7.2.

`okagent ssh-copy-id` installs the identity's public key on the host by
running `ssh-copy-id` against a temporary agent that serves only that key, so
its trial login and the install both sign with the token. The host part is the
destination, a `:port` suffix becomes `-p`, and any further arguments are
passed to `ssh-copy-id`. It needs an `ssh-copy-id` that takes keys from
`ssh-add -L`; the one shipped by current OpenSSH does.

Pass `-i [user@]host` (repeatable) to `ssh` or `mosh` to serve extra
identities from the temporary agent alongside the primary one. Only the
primary identity's key is used to log in, but the extra keys travel with
agent forwarding (`-A`), so `okagent ssh -i git@github.com ferris@example.com
-A` can run `git` on the remote host. Give `-i` before the identity, since a
literal `-i` for ssh must be passed after `--`.

A running agent can also be given keys on the fly. `ssh-add -s PROVIDER`
adds one and `ssh-add -e PROVIDER` removes it again, where `PROVIDER` is
either a bare `[user@]host` for a derived ed25519 key or a full key label as
printed by `okagent pubkey`: `<ssh://[user@]host|curve[|slot]>`. The key is
read from the OnlyKey when it is added, so `ssh-add -s` fails if the device
is unavailable or the slot is empty. Answer the PIN prompt with an empty
passphrase (or set `SSH_ASKPASS`). This is handy for long-lived agents and
for adding a key while another one is already being served:

```sh
okagent serve ferris@example.com &
ssh-add -s git@github.com                       # derived ed25519
ssh-add -s '<ssh://old@example.com|rsa|RSA1>'   # stored RSA key
ssh-add -L
ssh-add -e git@github.com
```

A plain private key can be loaded the same way with `ssh-add FILE`
(`ssh-add ~/.ssh/id_ed25519`). The agent then signs with it entirely in
memory, with no token and no button press; `ssh-add -d FILE` removes that key
(given the `.pub` of a token key, it removes that one too) and `ssh-add -D`
removes every identity, including those from the config file, until the agent
restarts or they are added back with `ssh-add -s`. ed25519, RSA, ECDSA
(`ecdsa-sha2-nistp256`, `-nistp384`, `-nistp521`) and DSA (`ssh-dss`) keys are
accepted, matching the key types `ssh-agent` itself can hold. An RSA key signs
`rsa-sha2-256` or `rsa-sha2-512` (a client asking for the legacy SHA-1
`ssh-rsa` signature is refused, as with the token); ECDSA uses the curve's own
digest and DSA uses SHA-1. DSA only works with OpenSSH builds that still enable
`ssh-dss`. A key stays loaded only for the life of the agent:

```sh
okagent serve ferris@example.com &
ssh-add ~/.ssh/id_ed25519
ssh-add ~/.ssh/id_rsa
ssh-add ~/.ssh/id_ecdsa
ssh-add -d ~/.ssh/id_rsa
```

FIDO security-key SSH keys work the same way. `ssh-add ~/.ssh/id_ed25519_sk`
(or `id_ecdsa_sk`) loads a key whose private half is actually on the
authenticator; when a client signs, okagent drives the device with a
pure-Rust CTAP2 client, so it works with any FIDO2 key (a YubiKey, the
OnlyKey's own FIDO applet, and so on) and needs no C library. A key made with
`ssh-keygen -t ed25519-sk` or `-t ecdsa-sk` must be touched to sign; a key
made with `-O verify-required` needs a PIN, which is not supported yet and is
refused with a clear error. By default the first authenticator other than
the OnlyKey is used; on a host with more than one, or to sign with the
OnlyKey's own FIDO applet, pass `--fido-device /dev/hidrawN` (or set
`fido-device` in the config) to choose one:

```sh
okagent serve ferris@example.com &
ssh-add ~/.ssh/id_ed25519_sk
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/okagent/agent.sock"
ssh ferris@example.com          # touch the key to sign
```

If the key's public key is already known there is no need to read it from
the device: start the agent with `--pubkey-file` and an add for one of those
identities is served from the file, so `ssh-add -s` works with the OnlyKey
unplugged. The provider string must match a label in the file exactly:

```sh
okagent pubkey git@github.com > ~/.ssh/onlykey.pub
okagent serve --pubkey-file ~/.ssh/onlykey.pub ferris@example.com &
ssh-add -s git@github.com                       # no device needed
```

```sh
okagent pubkey ferris@example.com >> authorized_keys   # copy to the server
okagent ssh-copy-id ferris@example.com                 # ...or let ssh-copy-id do it
okagent run ferris@example.com -- ssh example.com
okagent ssh ferris@example.com
okagent ssh ferris@example.com --host admin@server.example.com   # key ferris, login admin@server
okagent ssh -i git@github.com ferris@example.com -A     # forward the git key too
okagent ssh ferris@legacy.example.com --slot ECC3       # key stored by the OnlyKey app
okagent ssh ferris@old.example.com --slot RSA1          # RSA key stored by the OnlyKey app
eval "$(okagent serve --daemon ferris@example.com)"     # background agent
ssh-agent -k                                             # ...and stop it again
ssh-add -L
```

When a signature is requested, `okagent` prints something like

```
OnlyKey: enter 3 1 5 to sign as ferris@example.com (ssh-connection login as "ferris"), or press any button if challenge mode is off
```

on the controlling terminal, or on stderr when there is none. For a background
agent, pass `--notify-command "notify-send OnlyKey"` (or set it in the config)
to get a desktop notification instead.

### Config file

`~/.config/okagent/config.toml` (or `$XDG_CONFIG_HOME/okagent/config.toml`,
or `--config`) supplies defaults so identities need not be repeated:

```toml
curve = "ed25519"                       # default for identities without a curve
notify-command = "notify-send OnlyKey"  # optional
# socket = "/run/user/1000/okagent/agent.sock"
# pubkey-file = "/home/ferris/.ssh/onlykey.pub"
# log-file = "/home/ferris/.local/state/okagent.log"
# fido-device = "/dev/hidraw5"          # optional, for several FIDO keys

[[identity]]
name = "ferris@example.com"

[[identity]]
name = "git@github.com"
curve = "nistp256"

[[identity]]
name = "ferris@legacy.example.com"
slot = "ECC3"                           # stored key; `slot = 3` also works

[[identity]]
name = "ferris@old.example.com"
slot = "RSA1"                           # RSA keys take no curve
```

`pubkey-file` (or `--pubkey-file`) points at a file of lines from
`okagent pubkey`. Matching keys are listed even while the OnlyKey is unplugged
or locked, so `ssh` can pick the right key before you unlock the device. When
neither the command line nor the config file gives any identities, the file's
comments name them, so an exported file is all a background agent needs:

```sh
okagent pubkey ferris@example.com git@github.com > ~/.ssh/onlykey.pub
okagent serve --daemon --pubkey-file ~/.ssh/onlykey.pub
```

`pubkey`, `run`, `shell`, `serve`, `ssh`, `mosh` and `ssh-copy-id` all accept
the flag. The remote commands take a required identity, so for them the file
only preloads the matching key: `okagent ssh --pubkey-file ~/.ssh/onlykey.pub
ferris@example.com` hands `ssh` the right key before the device is unlocked.
The flag must come before the identity, since anything after it is passed
through to the remote command.

`run`, `shell` and `serve` also accept `-i`/`--identity ID` (repeatable) to
add identities on top of the positional, config-file or `--pubkey-file` list
instead of replacing it. So `okagent serve --pubkey-file keys.pub -i
extra@example.com` serves the keys named by the file plus `extra@example.com`.
`--slot` and `--curve` apply to these `-i` identities too.

`log-file` (or `--log-file`) appends log output to a file instead of stderr,
which is where a background agent's messages would otherwise be lost.

### systemd user unit

A user service is a safer alternative to `--daemon`:

```ini
# ~/.config/systemd/user/okagent.service
[Unit]
Description=OnlyKey SSH agent

[Service]
ExecStart=%h/.cargo/bin/okagent serve --notify-command "notify-send OnlyKey"
Restart=on-failure

[Install]
WantedBy=default.target
```

Then `systemctl --user enable --now okagent` and
`export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/okagent/agent.sock"`.

### launchd agent (macOS)

macOS has no `$XDG_RUNTIME_DIR`, so the default socket is
`$TMPDIR/okagent/agent.sock`. launchd does not expand `~` or `$TMPDIR`, so
give the service a fixed socket and absolute paths (replace `you`):

```xml
<!-- ~/Library/LaunchAgents/local.okagent.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>local.okagent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/you/.cargo/bin/okagent</string>
    <string>serve</string>
    <string>--socket</string><string>/Users/you/.okagent/agent.sock</string>
    <string>--notify-command</string>
    <string>/opt/homebrew/bin/terminal-notifier -title OnlyKey -message</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
```

Then `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.okagent.plist`
and `export SSH_AUTH_SOCK="$HOME/.okagent/agent.sock"`. The notifier is
`brew install terminal-notifier`; the prompt is appended as the message.

## The onlykey-agent library

```toml
[dependencies]
onlykey-agent = { git = "https://github.com/rustafariandev/onlykey-rs" }
```

```rust
use onlykey_agent::{Curve, KeySpec, OnlyKey, challenge::TtyPrompt, ssh_key::HashAlg};

let key = KeySpec::derived("ferris@example.com".parse()?, Curve::Ed25519);
let mut device = OnlyKey::open()?;                       // finds the token, syncs its clock
let public = device.ssh_public_key(&key)?;
println!("{}", public.to_openssh()?);                    // authorized_keys line

// Shows the challenge on the terminal, waits for the buttons, verifies the result.
// The hash only matters for RSA keys.
let sig = device.ssh_sign(&key, &public, b"hello", HashAlg::Sha512, None, &TtyPrompt)?;

// Keys the OnlyKey app wrote into slots ECC3 and RSA1.
let stored = KeySpec::stored("ferris@example.com".parse()?, Curve::Ed25519, "ECC3".parse()?);
println!("{}", device.ssh_public_key(&stored)?.to_openssh()?);
let rsa = KeySpec::rsa("ferris@example.com".parse()?, "RSA1".parse()?);
println!("{}", device.ssh_public_key(&rsa)?.to_openssh()?);
```

The crate docs (`cargo doc --open`) show how to run the agent from your own
program and describe each layer. The seams:

- `ChallengeSink` decides how the challenge reaches the user: `TtyPrompt`,
  `CommandNotifier` (run a program such as `notify-send`), `MultiSink`, and
  `RecordingSink` for tests.
- `HidTransport` is the boundary to the USB stack: `HidapiTransport` for
  hardware, `transport::fake::ScriptedTransport` for scripted exchanges, or
  your own implementation.
- `Agent::handle` is the whole agent as a function from request body to reply
  body, for serving over something other than a unix socket.
- `protocol`, `device` and `keys` are public for callers that need the raw
  key or signature bytes rather than SSH types.
- The `serde` feature derives `Serialize`/`Deserialize` on `Curve`.
- `ssh_key` is re-exported so `PublicKey` and `Signature` can be named
  without pinning the version yourself.

Examples: `cargo run --example pubkey -- ferris@example.com` and
`echo -n hi | cargo run --example sign -- ferris@example.com`.

## How it works

- The identity is transliterated to ASCII and hashed with SHA-256. A
  `scheme://`, `:port` or `/path` is accepted and ignored, as in the Python
  agent.
- Public key: `OKGETPUBKEY` with slot 132 and payload `curve tag || hash`.
- Signature: `OKSIGN` with slot 201 (ed25519) or 202 (nistp256) and payload
  `data || hash`, split into 57-byte HID reports. The device strips the hash,
  derives the key, and signs `data`. The challenge digits are bytes 0, 15 and
  31 of `SHA-256(data || hash)`, each `% 6 + 1`.
- The firmware reassembles at most 13 reports, 741 bytes, and answers a 14th
  with "packets received exceeded size limit". Ed25519 signs the message
  itself, so an ed25519 blob is limited to 709 bytes (derived) or 741 bytes
  (stored); SSH authentication requests are far smaller. For nistp256 the
  token signs `SHA-256(data)` and takes a 32-byte payload as that digest
  ready-made, so the agent sends the digest instead of the data (the same
  deterministic signature results, verified on hardware) and a nistp256 blob
  can be any length, as can RSA. After a size error the firmware keeps the
  half-assembled request for about five seconds and rejects anything sent in
  that window.
- Stored keys use the slot number itself, 101 to 116 for `ECC1` to `ECC16`:
  `OKGETPUBKEY` with that slot (the same payload is sent and ignored), and
  `OKSIGN` with that slot and `data` alone, so the challenge is over
  `SHA-256(data)`. This is what the Python agent's `--skey ECC3` does. The
  slot's key type is fixed when it is written, so the reply is checked
  against the requested curve. The key comment gains a third field,
  `<ssh://ferris@example.com|ed25519|ECC3>`, so a derived and a stored key for
  the same identity never share a label.
- RSA keys use slots 1 to 4 for `RSA1` to `RSA4`. `OKGETPUBKEY` is sent with
  tag `0x00 || hash` and the token answers with the modulus alone, 256 or 512
  bytes over four or eight reports (the exponent is always 65537); the agent
  reads until the token goes quiet, so the key size need not be declared.
  `OKSIGN` carries `SHA-256(data)` or `SHA-512(data)`, chosen by the SSH
  client's `rsa-sha2-256` / `rsa-sha2-512` request flag; the token applies
  the PKCS#1 v1.5 padding and returns the signature over four or eight
  reports. The challenge digits are over `SHA-256(digest)`. The comment is
  `<ssh://ferris@example.com|rsa|RSA1>`.
- FIDO `sk-` keys carry no secret: `ssh-add FILE` sends the public key,
  application and key handle, which the agent holds. Signing opens the
  authenticator's CTAPHID interface (HID usage page `0xF1D0`), allocates a
  channel with `CTAPHID_INIT`, and sends CTAP2 `authenticatorGetAssertion`
  with `rpId = application`, `clientDataHash = SHA-256(data)` and the key
  handle in the allow list. The assertion signs `SHA-256(application) ||
  flags || counter || SHA-256(data)`, which is exactly the SSH `sk-`
  signature, so the flags and counter from the authenticator data are appended
  to the signature as `PROTOCOL.u2f` requires. The whole exchange is a
  pure-Rust implementation of CTAPHID and CTAP2, with CBOR from `minicbor`.
- Every signature is verified against the public key before it is returned.
  Any device error, timeout or wrong challenge answers the SSH client with
  `SSH_AGENT_FAILURE` and keeps the agent running.
- `SSH2_AGENTC_REQUEST_IDENTITIES`, `SSH2_AGENTC_SIGN_REQUEST`,
  `SSH_AGENTC_LOCK` and `SSH_AGENTC_UNLOCK` are implemented. `ssh-add -x`
  locks the agent with a passphrase (kept only as a salted hash) and until
  `ssh-add -X` unlocks it the agent lists no keys and refuses to sign, add
  or remove keys; this is separate from the OnlyKey's PIN. `SSH_AGENTC_ADD_SMARTCARD_KEY` (and its
  constrained form) backs `ssh-add -s`, which adds the identity named by the
  provider string to a running agent; `SSH_AGENTC_REMOVE_SMARTCARD_KEY`
  backs `ssh-add -e`. The key is derived and verified against the token when
  it is added, so an absent device, an empty slot or a bad provider is
  reported as `SSH_AGENT_FAILURE`. Only the lifetime constraint of
  `ssh-add -t` is honoured, for `ssh-add -s` and `ssh-add FILE` alike; the
  provider's PIN is ignored, and the confirm constraint (`ssh-add -c`, which
  the agent cannot honour) and destination or certificate constraints are
  refused.
  `SSH2_AGENTC_ADD_IDENTITY` (and its constrained form) backs `ssh-add FILE`,
  which loads a plain ed25519, RSA, ECDSA or DSA private key into the agent;
  the agent signs with it in memory, with no token and no challenge, and `SSH2_AGENTC_REMOVE_IDENTITY`
  / `SSH_AGENTC_REMOVE_ALL_IDENTITIES` back `ssh-add -d` and `-D`. The key
  types the agent can load are pluggable: implement
  `onlykey_agent::agent::KeyDecoder` and register it with
  `Agent::with_key_type` (or `register_key_type`); the built-in ed25519, RSA,
  ECDSA, DSA and FIDO `sk-` types are registered the same way, and a later
  registration under a name wins. An in-memory key is signed by a
  `LocalKey` implementation. SSH protocol extension
  requests are pluggable too: implement `onlykey_agent::agent::Extension` and
  register it with `Agent::with_extension` (or `register_extension`), and the
  handler answers the `SSH_AGENTC_EXTENSION` requests whose name it matches,
  seeing whether the agent is locked through `ExtensionContext`. A handler is
  not refused automatically while locked, so it decides for itself.
  Unregistered extensions get `SSH_AGENT_EXTENSION_FAILURE` and the SSH
  protocol 1 listing an empty `SSH_AGENT_RSA_IDENTITIES_ANSWER`, as OpenSSH's
  agent replies; everything else gets a failure reply, which OpenSSH treats as
  "unsupported".

Differences from the Python agent:

- A payload whose length is a multiple of 57 is sent correctly (the Python
  client never terminates it and the device times out).
- The socket is created with owner-only permissions, and a live socket is
  never replaced.
- The challenge prompt goes to the terminal or a notify command, not stdout.

## Development

```sh
cargo test --workspace          # unit tests plus end-to-end tests with ssh-add / ssh-keygen
cargo clippy --workspace --all-targets
```

`tests/goldens.json` holds vectors recorded from the Python implementation
(identity hashes, HID frames, challenge digits, `.pub` lines). The end-to-end
tests run the real agent against a fake token that actually signs.

With hardware attached:

```sh
okagent status
okagent pubkey ferris@example.com             # must equal the Python agent's output
okagent debug-sign ferris@example.com         # hidden; 114-byte payload proves 57-multiple chunking
okagent run ferris@example.com -- ssh-add -L
okagent pubkey ferris@example.com --slot ECC3 # same key as `onlykey-agent ferris@example.com -sk ECC3`
okagent pubkey ferris@example.com --slot RSA1 # same key as `onlykey-agent ferris@example.com -sk RSA1 -e rsa2048`
```

An empty ECC slot answers "Error no ECC Private Key set in this slot" and an
empty RSA slot "Error no RSA Private Key set in this slot"; ECC slots above
16 get no answer at all from firmware v3.0.4. Checked on hardware so far:
derived ed25519 and stored RSA (2048-bit) public keys are byte-identical to
the Python agent's. `OKAGENT_LOG=onlykey_agent=trace` logs every report the
token sends, which is the quickest way to see what a slot really answers.

## License

MIT.
