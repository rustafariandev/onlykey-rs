# onlykey-rs

SSH keys on an [OnlyKey](https://onlykey.io) hardware token, from Rust.

A clean-room port of the SSH half of the Python
[`onlykey-agent`](https://github.com/trustcrypto/onlykey-agent). The private
key never leaves the token: it is re-derived on the device from an identity
string such as `james@example.com` for every operation, and each signature is
confirmed by entering a 3-digit challenge on the buttons. Given the same
identity and curve this port derives exactly the same public key as the
Python agent, so existing `authorized_keys` entries keep working.

Two crates:

- **`okagent`**: a command-line SSH agent.
- **`onlykey-agent`**: the library underneath it.

Scope: SSH only (no GPG, no age), the original OnlyKey (not DUO), Linux.

## Setup

- A Rust toolchain (edition 2024). No C libraries: the HID backend is pure
  Rust and reads `/dev/hidraw*` directly.
- A udev rule so the device can be opened without root. Copy
  `49-onlykey.rules` from the [OnlyKey docs](https://docs.crp.to/linux.html)
  to `/etc/udev/rules.d/` and replug the device. "Permission denied" means
  the rule is missing.

```sh
cargo install --git https://github.com/rustafariandev/onlykey-rs okagent
```

## okagent

| Command | What it does |
| --- | --- |
| `okagent status` | Firmware version and lock state of the attached token. |
| `okagent pubkey ID...` | Public keys in `authorized_keys` format. |
| `okagent run ID... -- CMD` | Run a command with a temporary agent in `SSH_AUTH_SOCK`. |
| `okagent shell ID...` | Start `$SHELL` with a temporary agent. |
| `okagent ssh ID [ARGS]` | Connect with ssh; the host part of the identity is the destination. |
| `okagent serve [ID...]` | Long-lived agent on a unix socket. |

An identity is `[user@]host`. Pass `--curve nistp256` for a P-256 key; the
default is ed25519. Identities can be omitted when the config file lists them.

```sh
okagent pubkey james@example.com >> authorized_keys   # copy to the server
okagent run james@example.com -- ssh example.com
okagent ssh james@example.com
eval "$(okagent serve --daemon james@example.com)"     # background agent
ssh-add -L
```

When a signature is requested, `okagent` prints something like

```
OnlyKey: enter 3 1 5 to sign as james@example.com (ssh-connection login as "james"), or press any button if challenge mode is off
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
# pubkey-file = "/home/james/.ssh/onlykey.pub"

[[identity]]
name = "james@example.com"

[[identity]]
name = "git@github.com"
curve = "nistp256"
```

`pubkey-file` (or `--pubkey-file`) points at a file of lines from
`okagent pubkey`. Matching keys are listed even while the OnlyKey is unplugged
or locked, so `ssh` can pick the right key before you unlock the device.

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

## The onlykey-agent library

```toml
[dependencies]
onlykey-agent = { git = "https://github.com/rustafariandev/onlykey-rs" }
```

```rust
use onlykey_agent::{Curve, Identity, OnlyKey, challenge::TtyPrompt};

let identity: Identity = "james@example.com".parse()?;
let mut device = OnlyKey::open()?;                       // finds the token, syncs its clock
let key = device.ssh_public_key(&identity, Curve::Ed25519)?;
println!("{}", key.to_openssh()?);                       // authorized_keys line

// Shows the challenge on the terminal, waits for the buttons, verifies the result.
let sig = device.ssh_sign(&identity, Curve::Ed25519, &key, b"hello", None, &TtyPrompt)?;
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
  64-byte key or signature rather than SSH types.
- The `serde` feature derives `Serialize`/`Deserialize` on `Curve`.
- `ssh_key` is re-exported so `PublicKey` and `Signature` can be named
  without pinning the version yourself.

Examples: `cargo run --example pubkey -- james@example.com` and
`echo -n hi | cargo run --example sign -- james@example.com`.

## How it works

- The identity is transliterated to ASCII and hashed with SHA-256. A
  `scheme://`, `:port` or `/path` is accepted and ignored, as in the Python
  agent.
- Public key: `OKGETPUBKEY` with slot 132 and payload `curve tag || hash`.
- Signature: `OKSIGN` with slot 201 (ed25519) or 202 (nistp256) and payload
  `data || hash`, split into 57-byte HID reports. The device strips the hash,
  derives the key, and signs `data`. The challenge digits are bytes 0, 15 and
  31 of `SHA-256(data || hash)`, each `% 6 + 1`.
- Every signature is verified against the derived public key before it is
  returned. Any device error, timeout or wrong challenge answers the SSH
  client with `SSH_AGENT_FAILURE` and keeps the agent running.
- Only `SSH2_AGENTC_REQUEST_IDENTITIES` and `SSH2_AGENTC_SIGN_REQUEST` are
  implemented; everything else gets a failure reply, which OpenSSH treats as
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
okagent pubkey james@example.com             # must equal the Python agent's output
okagent debug-sign james@example.com         # hidden; 114-byte payload proves 57-multiple chunking
okagent run james@example.com -- ssh-add -L
```

## License

MIT.
