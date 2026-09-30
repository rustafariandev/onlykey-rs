//! Drives the agent over its unix socket with real OpenSSH tools.

mod common;

use common::SigningFake;
use onlykey_agent::agent::wire;
use onlykey_agent::agent::{self, Agent, Extension, ExtensionContext, ExtensionReply, Opener};
use onlykey_agent::challenge::RecordingSink;
use onlykey_agent::identity::{Curve, EccSlot, KeySource, KeySpec, RsaSlot, Slot};
use ssh_encoding::Decode;
use ssh_encoding::Encode;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

struct Harness {
    socket: std::path::PathBuf,
    sink: Arc<RecordingSink>,
    shutdown: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    _dir: tempfile::TempDir,
}

impl Harness {
    fn start(entries: Vec<KeySpec>) -> Self {
        let sink = Arc::new(RecordingSink::default());
        let opener: Opener = Arc::new(|| Ok(SigningFake::open()));
        let agent = Agent::new(entries, opener, sink.clone());
        Self::serve(agent, sink)
    }

    /// Serve an agent the caller built itself, for tests that register
    /// extensions or otherwise tweak it before the socket opens.
    fn serve(agent: Agent, sink: Arc<RecordingSink>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let agent = Arc::new(agent);
        let (listener, guard) = agent::bind_socket(&socket).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = {
            let shutdown = shutdown.clone();
            std::thread::spawn(move || {
                let _guard = guard;
                agent::serve(listener, agent, shutdown)
            })
        };
        Harness {
            socket,
            sink,
            shutdown,
            server: Some(server),
            _dir: dir,
        }
    }

    fn cmd(&self, program: &str) -> Command {
        let mut c = Command::new(program);
        c.env("SSH_AUTH_SOCK", &self.socket);
        c
    }

    fn challenges(&self) -> usize {
        self.sink.0.lock().unwrap().len()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            server.join().unwrap().unwrap();
        }
    }
}

fn entries() -> Vec<KeySpec> {
    vec![
        KeySpec::derived("ferris@example.com".parse().unwrap(), Curve::Ed25519),
        KeySpec::derived("git@github.com".parse().unwrap(), Curve::NistP256),
    ]
}

fn stored(identity: &str, curve: Curve, slot: u8) -> KeySpec {
    KeySpec::stored(
        identity.parse().unwrap(),
        curve,
        EccSlot::new(slot - 100).unwrap(),
    )
}

fn rsa(identity: &str, slot: u8) -> KeySpec {
    KeySpec::rsa(identity.parse().unwrap(), RsaSlot::new(slot).unwrap())
}

/// Three usable stored keys plus three that the fake token rejects: an empty
/// ECC slot, a slot asked for with the wrong curve, and an empty RSA slot.
fn stored_entries() -> Vec<KeySpec> {
    vec![
        stored(
            "ferris@example.com",
            Curve::Ed25519,
            common::STORED_ED25519_SLOT,
        ),
        stored("git@github.com", Curve::NistP256, common::STORED_P256_SLOT),
        stored("nobody@example.com", Curve::Ed25519, 110),
        stored(
            "ferris@example.com",
            Curve::NistP256,
            common::STORED_ED25519_SLOT,
        ),
        rsa("ferris@old.example.com", common::STORED_RSA_SLOT),
        rsa("nobody@example.com", 3),
    ]
}

/// Run `ssh-add` with `passphrase` supplied through SSH_ASKPASS.
fn ssh_add_with_passphrase(h: &Harness, dir: &Path, flag: &str, passphrase: &str) -> bool {
    let askpass = dir.join("askpass.sh");
    std::fs::write(&askpass, format!("#!/bin/sh\necho '{passphrase}'\n")).unwrap();
    std::fs::set_permissions(
        &askpass,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    h.cmd("ssh-add")
        .arg(flag)
        .env("SSH_ASKPASS", &askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

fn listed_keys(h: &Harness) -> usize {
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("ssh-") || l.starts_with("ecdsa-"))
        .count()
}

#[test]
fn ssh_add_locks_and_unlocks_the_agent() {
    if !have("ssh-add") {
        eprintln!("ssh-add not installed; skipping");
        return;
    }
    let h = Harness::start(entries());
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(listed_keys(&h), 2);
    assert!(ssh_add_with_passphrase(&h, dir.path(), "-x", "hunter2"));
    assert_eq!(listed_keys(&h), 0, "a locked agent lists no keys");
    assert!(!ssh_add_with_passphrase(&h, dir.path(), "-X", "wrong"));
    assert_eq!(listed_keys(&h), 0);
    assert!(ssh_add_with_passphrase(&h, dir.path(), "-X", "hunter2"));
    assert_eq!(listed_keys(&h), 2);
    assert_eq!(h.challenges(), 0);
}

/// Run `ssh-add -s`/`-e` with `provider`, answering the PKCS#11 PIN prompt
/// with an empty passphrase so no terminal is needed. Also works on OpenSSH
/// versions without `-P`.
fn ssh_add_card(h: &Harness, dir: &Path, flag: &str, provider: &str) -> bool {
    let askpass = dir.join("askpass.sh");
    std::fs::write(&askpass, "#!/bin/sh\necho\n").unwrap();
    std::fs::set_permissions(
        &askpass,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    h.cmd("ssh-add")
        .arg(flag)
        .arg(provider)
        .env("SSH_ASKPASS", &askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

#[test]
fn ssh_add_smartcard_adds_removes_and_signs() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let h = Harness::start(Vec::new());
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(listed_keys(&h), 0);

    // A bare identity means a derived ed25519 key.
    assert!(ssh_add_card(&h, dir.path(), "-s", "ferris@example.com"));
    assert_eq!(listed_keys(&h), 1);
    // Adding the same key again is a no-op that still succeeds.
    assert!(ssh_add_card(&h, dir.path(), "-s", "ferris@example.com"));
    assert_eq!(listed_keys(&h), 1);

    // A full label selects the curve and a stored slot (ECC4 holds P-256).
    assert!(ssh_add_card(
        &h,
        dir.path(),
        "-s",
        "<ssh://git@github.com|nist256p1|ECC4>"
    ));
    assert_eq!(listed_keys(&h), 2);

    // The added key really signs.
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let line = text
        .lines()
        .find(|l| l.ends_with("<ssh://ferris@example.com|ed25519>"))
        .expect("added key is listed");
    sign_and_check(&h, dir.path(), line, "added-ed25519");

    // `ssh-add -e` takes the keys away again.
    assert!(ssh_add_card(&h, dir.path(), "-e", "ferris@example.com"));
    assert_eq!(listed_keys(&h), 1);
    assert!(ssh_add_card(
        &h,
        dir.path(),
        "-e",
        "<ssh://git@github.com|nist256p1|ECC4>"
    ));
    assert_eq!(listed_keys(&h), 0);
    assert!(!ssh_add_card(&h, dir.path(), "-e", "ferris@example.com"));
}

/// Run `ssh-add FILE`, loading a plain private key from disk.
fn ssh_add_file(h: &Harness, path: &Path) -> bool {
    h.cmd("ssh-add")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// `ssh-add FILE` loads a plain ed25519 key into the agent. It signs entirely
/// in software (no token, no challenge), and `-d`/`-D` take it away again.
#[test]
fn ssh_add_loads_a_regular_ed25519_key() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let h = Harness::start(entries());
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");
    let generated = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "regular@example.com", "-f"])
        .arg(&key_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(generated.success(), "ssh-keygen failed");

    assert_eq!(listed_keys(&h), 2, "the two derived keys");
    assert!(ssh_add_file(&h, &key_path));
    assert_eq!(listed_keys(&h), 3);

    // The added key really signs, without a challenge on the token.
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let line = text
        .lines()
        .find(|l| l.ends_with("regular@example.com"))
        .expect("added key is listed");
    assert!(line.starts_with("ssh-ed25519 "), "{line}");
    sign_and_check(&h, dir.path(), line, "regular-ed25519");
    assert_eq!(h.challenges(), 0, "a local key must not touch the token");

    // `ssh-add -d FILE` removes just that key; `-D` removes everything.
    assert!(ssh_add_file(&h, &key_path));
    assert!(
        h.cmd("ssh-add")
            .arg("-d")
            .arg(&key_path)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(listed_keys(&h), 2);
    assert!(ssh_add_file(&h, &key_path));
    assert!(h.cmd("ssh-add").arg("-D").status().unwrap().success());
    assert_eq!(listed_keys(&h), 0);
}

/// `ssh-add FILE` loads a plain RSA key too, signing in software with the
/// digest the client asks for (`rsa-sha2-512` for `ssh-keygen -Y sign`).
#[test]
fn ssh_add_loads_a_regular_rsa_key() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let h = Harness::start(entries());
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_rsa");
    let generated = Command::new("ssh-keygen")
        .args([
            "-t",
            "rsa",
            "-b",
            "2048",
            "-N",
            "",
            "-C",
            "regular-rsa@example.com",
            "-f",
        ])
        .arg(&key_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(generated.success(), "ssh-keygen failed");

    assert_eq!(listed_keys(&h), 2, "the two derived keys");
    assert!(ssh_add_file(&h, &key_path));
    assert_eq!(listed_keys(&h), 3);

    // The added key really signs, without a challenge on the token.
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let line = text
        .lines()
        .find(|l| l.ends_with("regular-rsa@example.com"))
        .expect("added key is listed");
    assert!(line.starts_with("ssh-rsa "), "{line}");
    sign_and_check(&h, dir.path(), line, "regular-rsa");
    assert_eq!(h.challenges(), 0, "a local key must not touch the token");

    // `ssh-add -d FILE` removes just that key.
    assert!(ssh_add_file(&h, &key_path));
    assert!(
        h.cmd("ssh-add")
            .arg("-d")
            .arg(&key_path)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(listed_keys(&h), 2);
}

/// `ssh-add FILE` loads a plain ECDSA key on any NIST curve, signing in
/// software with the curve's own digest.
#[test]
fn ssh_add_loads_a_regular_ecdsa_key() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    for (bits, name) in [(256, "nistp256"), (384, "nistp384"), (521, "nistp521")] {
        let h = Harness::start(entries());
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(format!("id_ecdsa_{bits}"));
        let comment = format!("regular-{name}@example.com");
        let generated = Command::new("ssh-keygen")
            .args([
                "-t",
                "ecdsa",
                "-b",
                &bits.to_string(),
                "-N",
                "",
                "-C",
                &comment,
                "-f",
            ])
            .arg(&key_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(generated.success(), "ssh-keygen failed for {name}");

        assert_eq!(listed_keys(&h), 2, "the two derived keys");
        assert!(ssh_add_file(&h, &key_path), "{name}");

        let out = h.cmd("ssh-add").arg("-L").output().unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let line = text
            .lines()
            .find(|l| l.ends_with(&comment))
            .unwrap_or_else(|| panic!("{name} key is listed: {text}"));
        assert!(line.starts_with(&format!("ecdsa-sha2-{name} ")), "{line}");
        sign_and_check(&h, dir.path(), line, name);
        assert_eq!(h.challenges(), 0, "a local key must not touch the token");

        assert!(
            h.cmd("ssh-add")
                .arg("-d")
                .arg(&key_path)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(listed_keys(&h), 2, "{name}");
    }
}

/// `ssh-add FILE` loads a plain DSA key where OpenSSH still supports DSA.
/// Since OpenSSH 9.8 `ssh-dss` is compiled out by default, so this skips on
/// modern builds; the agent path is covered by unit tests either way.
#[test]
fn ssh_add_loads_a_regular_dsa_key() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let h = Harness::start(entries());
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_dsa");
    let generated = Command::new("ssh-keygen")
        .args(["-t", "dsa", "-N", "", "-C", "regular-dsa@example.com", "-f"])
        .arg(&key_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    if !generated.success() {
        eprintln!("ssh-keygen has no DSA support; skipping");
        return;
    }

    assert!(ssh_add_file(&h, &key_path));
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let line = text
        .lines()
        .find(|l| l.ends_with("regular-dsa@example.com"))
        .expect("added key is listed");
    assert!(line.starts_with("ssh-dss "), "{line}");
    sign_and_check(&h, dir.path(), line, "regular-dsa");
    assert_eq!(h.challenges(), 0, "a local key must not touch the token");
}

#[test]
fn ssh_add_smartcard_honours_a_lifetime() {
    if !have("ssh-add") {
        eprintln!("ssh-add not installed; skipping");
        return;
    }
    let h = Harness::start(Vec::new());
    // The constrained request (ssh-add -t) is accepted and the key is served.
    assert!(
        h.cmd("ssh-add")
            .args(["-t", "60", "-s", "ferris@example.com"])
            .env("SSH_ASKPASS", "/bin/true")
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", ":0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(listed_keys(&h), 1);
}

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

#[test]
fn ssh_add_lists_both_keys() {
    if !have("ssh-add") {
        eprintln!("ssh-add not installed; skipping");
        return;
    }
    let h = Harness::start(entries());
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "ssh-add -L failed: {text}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(
        lines[0].starts_with("ssh-ed25519 ")
            && lines[0].ends_with("<ssh://ferris@example.com|ed25519>")
    );
    assert!(
        lines[1].starts_with("ecdsa-sha2-nistp256 ")
            && lines[1].ends_with("<ssh://git@github.com|nist256p1>")
    );
    assert_eq!(h.challenges(), 0);
}

fn sign_and_check(h: &Harness, dir: &Path, pub_line: &str, name: &str) {
    let pub_path = dir.join(format!("{name}.pub"));
    std::fs::write(&pub_path, format!("{pub_line}\n")).unwrap();
    let msg_path = dir.join(format!("{name}.msg"));
    std::fs::write(&msg_path, b"the quick brown fox\n").unwrap();

    let status = h
        .cmd("ssh-keygen")
        .args(["-Y", "sign", "-q", "-n", "okagent-test", "-f"])
        .arg(&pub_path)
        .arg(&msg_path)
        .status()
        .unwrap();
    assert!(status.success(), "ssh-keygen -Y sign failed for {name}");
    let sig_path = dir.join(format!("{name}.msg.sig"));
    assert!(sig_path.exists());

    let mut check = Command::new("ssh-keygen")
        .args(["-Y", "check-novalidate", "-n", "okagent-test", "-f"])
        .arg(&pub_path)
        .arg("-s")
        .arg(&sig_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    check
        .stdin
        .take()
        .unwrap()
        .write_all(b"the quick brown fox\n")
        .unwrap();
    let out = check.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "signature check failed for {name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn ssh_keygen_signs_with_both_curves() {
    if !have("ssh-keygen") || !have("ssh-add") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let h = Harness::start(entries());
    let dir = tempfile::tempdir().unwrap();
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    sign_and_check(&h, dir.path(), lines[0], "ed25519");
    sign_and_check(&h, dir.path(), lines[1], "p256");
    let shown = h.sink.0.lock().unwrap();
    assert_eq!(shown.len(), 2);
    assert_eq!(shown[0].identity, "ferris@example.com");
    assert_eq!(
        shown[0].subject.as_deref(),
        Some("signature in namespace \"okagent-test\"")
    );
    assert_eq!(shown[1].identity, "git@github.com");
}

#[test]
fn stored_keys_are_listed_and_sign_without_identity_hash() {
    if !have("ssh-keygen") || !have("ssh-add") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let h = Harness::start(stored_entries());
    let dir = tempfile::tempdir().unwrap();
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "ssh-add -L failed: {text}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "unusable slots must be skipped: {text}");
    assert!(
        lines[0].starts_with("ssh-ed25519 ")
            && lines[0].ends_with("<ssh://ferris@example.com|ed25519|ECC3>"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("ecdsa-sha2-nistp256 ")
            && lines[1].ends_with("<ssh://git@github.com|nist256p1|ECC4>"),
        "{}",
        lines[1]
    );
    assert!(
        lines[2].starts_with("ssh-rsa ")
            && lines[2].ends_with("<ssh://ferris@old.example.com|rsa|RSA1>"),
        "{}",
        lines[2]
    );
    // A stored key does not depend on the identity: the same slot under
    // another name yields the same key.
    let other = Harness::start(vec![stored(
        "other@example.org",
        Curve::Ed25519,
        common::STORED_ED25519_SLOT,
    )]);
    let out = other.cmd("ssh-add").arg("-L").output().unwrap();
    let other_line = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        other_line.split_whitespace().nth(1),
        lines[0].split_whitespace().nth(1)
    );

    sign_and_check(&h, dir.path(), lines[0], "stored-ed25519");
    sign_and_check(&h, dir.path(), lines[1], "stored-p256");
    sign_and_check(&h, dir.path(), lines[2], "stored-rsa");
    let shown = h.sink.0.lock().unwrap();
    assert_eq!(shown.len(), 3);
    assert_eq!(shown[0].identity, "ferris@example.com");
    assert_eq!(
        shown[0].source,
        KeySource::Stored(Slot::Ecc(EccSlot::new(3).unwrap()))
    );
    assert!(shown[0].message().contains("with stored key ECC3"));
    assert_eq!(
        shown[1].source,
        KeySource::Stored(Slot::Ecc(EccSlot::new(4).unwrap()))
    );
    assert_eq!(
        shown[2].source,
        KeySource::Stored(Slot::Rsa(RsaSlot::new(1).unwrap()))
    );
    assert!(shown[2].message().contains("with stored key RSA1"));
}

/// A client that asks an RSA key for a SHA-1 signature is refused, since the
/// token only signs SHA-2 digests.
#[test]
fn rsa_key_refuses_sha1_signature_requests() {
    let h = Harness::start(vec![rsa("ferris@old.example.com", common::STORED_RSA_SLOT)]);
    let reply = roundtrip(&h.socket, &[wire::SSH2_AGENTC_REQUEST_IDENTITIES]);
    let mut r = &reply[5..];
    let blob = Vec::<u8>::decode(&mut r).unwrap();
    let sign_request = |flags: u32| {
        let mut body = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
        blob.encode(&mut body).unwrap();
        b"data".as_slice().encode(&mut body).unwrap();
        flags.encode(&mut body).unwrap();
        body
    };
    assert_eq!(
        roundtrip(&h.socket, &sign_request(0)),
        vec![wire::SSH_AGENT_FAILURE]
    );
    assert_eq!(h.challenges(), 0);
    let reply = roundtrip(&h.socket, &sign_request(wire::SSH_AGENT_RSA_SHA2_256));
    assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);
    assert_eq!(h.challenges(), 1);
}

fn roundtrip(socket: &Path, body: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).unwrap();
    wire::write_frame(&mut stream, body).unwrap();
    wire::read_frame(&mut stream).unwrap().unwrap()
}

#[test]
fn unsupported_and_unknown_key_requests_get_failure_and_keep_connection() {
    let h = Harness::start(entries());
    // An add-identity with an empty key type is refused; extensions and the
    // SSH v1 listing get the replies OpenSSH's own agent gives.
    assert_eq!(
        roundtrip(&h.socket, &[17, 0, 0, 0, 0]),
        vec![wire::SSH_AGENT_FAILURE]
    );
    assert_eq!(
        roundtrip(&h.socket, &[wire::SSH_AGENTC_EXTENSION, 0, 0, 0, 0]),
        vec![wire::SSH_AGENT_EXTENSION_FAILURE]
    );
    assert_eq!(
        roundtrip(&h.socket, &[wire::SSH_AGENTC_REQUEST_RSA_IDENTITIES]),
        vec![wire::SSH_AGENT_RSA_IDENTITIES_ANSWER, 0, 0, 0, 0]
    );
    let mut body = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
    b"not a key".as_slice().encode(&mut body).unwrap();
    b"data".as_slice().encode(&mut body).unwrap();
    0u32.encode(&mut body).unwrap();
    // Two requests on one connection: failure must not close it.
    let mut stream = UnixStream::connect(&h.socket).unwrap();
    wire::write_frame(&mut stream, &body).unwrap();
    assert_eq!(
        wire::read_frame(&mut stream).unwrap().unwrap(),
        vec![wire::SSH_AGENT_FAILURE]
    );
    wire::write_frame(&mut stream, &[wire::SSH2_AGENTC_REQUEST_IDENTITIES]).unwrap();
    let reply = wire::read_frame(&mut stream).unwrap().unwrap();
    assert_eq!(reply[0], wire::SSH2_AGENT_IDENTITIES_ANSWER);
    assert_eq!(h.challenges(), 0);
}

struct Ping;

impl Extension for Ping {
    fn name(&self) -> &str {
        "ping@example.com"
    }

    fn handle(&self, _ctx: &ExtensionContext, data: &[u8]) -> ExtensionReply {
        if data == b"ping" {
            ExtensionReply::Success
        } else {
            ExtensionReply::Failure
        }
    }
}

#[test]
fn registered_extension_answers_over_the_socket() {
    let sink = Arc::new(RecordingSink::default());
    let opener: Opener = Arc::new(|| Ok(SigningFake::open()));
    let agent = Agent::new(entries(), opener, sink.clone()).with_extension(Ping);
    let h = Harness::serve(agent, sink);

    let mut body = vec![wire::SSH_AGENTC_EXTENSION];
    b"ping@example.com".as_slice().encode(&mut body).unwrap();
    body.extend_from_slice(b"ping");
    assert_eq!(roundtrip(&h.socket, &body), vec![wire::SSH_AGENT_SUCCESS]);

    // Unregistered names are still answered with the extension-failure code.
    let mut unknown = vec![wire::SSH_AGENTC_EXTENSION];
    b"nope@example.com".as_slice().encode(&mut unknown).unwrap();
    assert_eq!(
        roundtrip(&h.socket, &unknown),
        vec![wire::SSH_AGENT_EXTENSION_FAILURE]
    );
}
