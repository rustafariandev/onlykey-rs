//! Drives the agent over its unix socket with real OpenSSH tools.

mod common;

use common::SigningFake;
use okagent::agent::wire;
use okagent::agent::{self, Agent, Extension, ExtensionContext, ExtensionReply, Opener};
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
    ssh_add_card_args(h, dir, &[flag, provider])
}

/// Run `ssh-add` with `args`, answering any prompt with an empty passphrase.
fn ssh_add_card_args(h: &Harness, dir: &Path, args: &[&str]) -> bool {
    let askpass = dir.join("askpass.sh");
    std::fs::write(&askpass, "#!/bin/sh\necho\n").unwrap();
    std::fs::set_permissions(
        &askpass,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    h.cmd("ssh-add")
        .args(args)
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

/// Sign `pub_path` (a public key file) as user certificate `name-cert.pub`
/// with a fresh CA in `dir`, valid for an hour, returning the certificate
/// line.
fn certify(dir: &Path, pub_path: &Path) -> String {
    let ca = dir.join("ca");
    if !ca.exists() {
        let made = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "ca", "-f"])
            .arg(&ca)
            .status()
            .unwrap();
        assert!(made.success(), "ssh-keygen (CA) failed");
    }
    let signed = Command::new("ssh-keygen")
        .args(["-q", "-s"])
        .arg(&ca)
        .args(["-I", "okagent-test", "-n", "ferris", "-V", "-5m:+1h"])
        .arg(pub_path)
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(signed.success(), "ssh-keygen -s failed");
    let stem = pub_path.to_str().unwrap().strip_suffix(".pub").unwrap();
    std::fs::read_to_string(format!("{stem}-cert.pub"))
        .unwrap()
        .trim()
        .to_owned()
}

fn listing(h: &Harness) -> Vec<String> {
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("ssh-") || l.starts_with("ecdsa-"))
        .map(str::to_owned)
        .collect()
}

/// A certificate for a token key, attached with `ssh-add -s IDENTITY CERT`,
/// signs through the token.
#[test]
fn token_keys_serve_certificates() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let h = Harness::start(Vec::new());
    let dir = tempfile::tempdir().unwrap();
    assert!(ssh_add_card(&h, dir.path(), "-s", "ferris@example.com"));
    let key_line = listing(&h).pop().unwrap();
    let pub_path = dir.path().join("token.pub");
    std::fs::write(&pub_path, format!("{key_line}\n")).unwrap();
    let cert_line = certify(dir.path(), &pub_path);
    let cert_path = dir.path().join("token-cert.pub");
    assert!(ssh_add_card(&h, dir.path(), "-e", "ferris@example.com"));

    // `-C`: just the certificate. ssh-add exits 1 after `-C` even with
    // OpenSSH's agent; the listing tells.
    let cert_arg = cert_path.to_str().unwrap();
    ssh_add_card_args(
        &h,
        dir.path(),
        &["-C", "-s", "ferris@example.com", cert_arg],
    );
    let lines = listing(&h);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].starts_with("ssh-ed25519-cert-v01@openssh.com "));
    let before = h.challenges();
    sign_and_check(&h, dir.path(), &cert_line, "token-cert");
    assert_eq!(
        h.challenges(),
        before + 1,
        "the token signs for the certificate"
    );

    // Without `-C`, key and certificate; `-e` takes both away.
    assert!(ssh_add_card_args(
        &h,
        dir.path(),
        &["-s", "ferris@example.com", cert_arg]
    ));
    assert_eq!(listed_keys(&h), 2);
    assert!(ssh_add_card(&h, dir.path(), "-e", "ferris@example.com"));
    assert_eq!(listed_keys(&h), 0);
}

fn sign_body(keyblob: &[u8], data: &[u8]) -> Vec<u8> {
    let mut body = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
    keyblob.encode(&mut body).unwrap();
    data.encode(&mut body).unwrap();
    0u32.encode(&mut body).unwrap();
    body
}

fn session_bind_body(
    hostkey: &ssh_key::PublicKey,
    session_id: &[u8],
    signature: &[u8],
    forwarding: bool,
) -> Vec<u8> {
    let mut body = vec![wire::SSH_AGENTC_EXTENSION];
    "session-bind@openssh.com".encode(&mut body).unwrap();
    hostkey.to_bytes().unwrap().encode(&mut body).unwrap();
    session_id.encode(&mut body).unwrap();
    signature.encode(&mut body).unwrap();
    body.push(forwarding as u8);
    body
}

/// A key added with `ssh-add -c` asks the sink before every signature and is
/// refused when the user does not confirm.
#[test]
fn confirm_constrained_key_asks_before_each_signature() {
    let h = Harness::start(Vec::new());

    let pair = ssh_key::private::Ed25519Keypair::from_seed(&[0x31; 32]);
    let public = ssh_key::PublicKey::new(
        ssh_key::public::KeyData::Ed25519(pair.public),
        "confirmed@example.com",
    );
    let keyblob = public.to_bytes().unwrap();

    let mut add = vec![wire::SSH2_AGENTC_ADD_ID_CONSTRAINED];
    "ssh-ed25519".encode(&mut add).unwrap();
    pair.encode(&mut add).unwrap();
    "confirmed@example.com".encode(&mut add).unwrap();
    wire::SSH_AGENT_CONSTRAIN_CONFIRM.encode(&mut add).unwrap();
    assert_eq!(roundtrip(&h.socket, &add), vec![wire::SSH_AGENT_SUCCESS]);

    // The user declines (no answer is queued): the signature is refused.
    assert_eq!(
        roundtrip(&h.socket, &sign_body(&keyblob, b"data")),
        vec![wire::SSH_AGENT_FAILURE]
    );
    // The user agrees: the signature is served.
    h.sink.2.lock().unwrap().push_back(true);
    let reply = roundtrip(&h.socket, &sign_body(&keyblob, b"data"));
    assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);
}

/// A connection bound with `session-bind@openssh.com` for forwarding, as the
/// agent connection `ssh -A` relays from a remote host looks.
fn forwarded_connection(h: &Harness) -> UnixStream {
    use signature::Signer;

    let host = ssh_key::private::PrivateKey::new(
        ssh_key::private::KeypairData::Ed25519(ssh_key::private::Ed25519Keypair::from_seed(
            &[9; 32],
        )),
        "host",
    )
    .unwrap();
    let session_id = b"forwarded session";
    let signature = Signer::sign(&host, session_id);
    let mut signature_bytes = Vec::new();
    signature.encode(&mut signature_bytes).unwrap();

    let mut stream = UnixStream::connect(&h.socket).unwrap();
    let bind = session_bind_body(host.public_key(), session_id, &signature_bytes, true);
    assert_eq!(exchange(&mut stream, &bind), vec![wire::SSH_AGENT_SUCCESS]);
    stream
}

/// Send one request on an open connection and read its reply.
fn exchange(stream: &mut UnixStream, body: &[u8]) -> Vec<u8> {
    wire::write_frame(stream, body).unwrap();
    wire::read_frame(stream).unwrap().unwrap()
}

/// The key blobs a local connection lists, in order.
fn identity_blobs(h: &Harness) -> Vec<Vec<u8>> {
    let reply = roundtrip(&h.socket, &[wire::SSH2_AGENTC_REQUEST_IDENTITIES]);
    assert_eq!(reply[0], wire::SSH2_AGENT_IDENTITIES_ANSWER);
    let mut rest = &reply[1..];
    let count = u32::decode(&mut rest).unwrap();
    (0..count)
        .map(|_| {
            let blob = Vec::<u8>::decode(&mut rest).unwrap();
            String::decode(&mut rest).unwrap();
            blob
        })
        .collect()
}

/// A forwarded connection can neither re-add nor remove a token key: the
/// key's label is all a remote host would need to re-add it without the
/// constraints the user gave it locally.
#[test]
fn forwarded_connection_cannot_manage_token_keys() {
    let h = Harness::start(Vec::new());
    let provider = "ferris@example.com";

    let mut add = vec![wire::SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED];
    provider.encode(&mut add).unwrap();
    "".encode(&mut add).unwrap();
    wire::SSH_AGENT_CONSTRAIN_CONFIRM.encode(&mut add).unwrap();
    assert_eq!(roundtrip(&h.socket, &add), vec![wire::SSH_AGENT_SUCCESS]);
    let keys = identity_blobs(&h);
    assert_eq!(keys.len(), 1);

    let mut forwarded = forwarded_connection(&h);
    let mut readd = vec![wire::SSH_AGENTC_ADD_SMARTCARD_KEY];
    provider.encode(&mut readd).unwrap();
    "".encode(&mut readd).unwrap();
    assert_eq!(
        exchange(&mut forwarded, &readd),
        vec![wire::SSH_AGENT_FAILURE]
    );
    let mut remove = vec![wire::SSH_AGENTC_REMOVE_SMARTCARD_KEY];
    provider.encode(&mut remove).unwrap();
    "".encode(&mut remove).unwrap();
    assert_eq!(
        exchange(&mut forwarded, &remove),
        vec![wire::SSH_AGENT_FAILURE]
    );

    // The key is still served, and still asks before each signature.
    assert_eq!(identity_blobs(&h), keys);
    assert_eq!(
        roundtrip(&h.socket, &sign_body(&keys[0], b"data")),
        vec![wire::SSH_AGENT_FAILURE]
    );
    h.sink.2.lock().unwrap().push_back(true);
    let reply = roundtrip(&h.socket, &sign_body(&keys[0], b"data"));
    assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);
}

/// `ssh-add -c FILE` constrains the key and its certificate alike; removing
/// the plain key leaves the certificate served, still asking before each
/// signature.
#[test]
fn certificate_keeps_its_constraints_when_its_key_is_removed() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let h = Harness::start(Vec::new());
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");
    let made = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "cert@example.com"])
        .arg("-f")
        .arg(&key_path)
        .status()
        .unwrap();
    assert!(made.success());
    let pub_path = key_path.with_extension("pub");
    let cert_line = certify(dir.path(), &pub_path);
    let added = h
        .cmd("ssh-add")
        .arg("-c")
        .arg(&key_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(added.success());

    let plain = ssh_key::PublicKey::read_openssh_file(&pub_path)
        .unwrap()
        .to_bytes()
        .unwrap();
    let cert = ssh_key::Certificate::from_openssh(&cert_line)
        .unwrap()
        .to_bytes()
        .unwrap();
    let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
    plain.encode(&mut remove).unwrap();
    assert_eq!(roundtrip(&h.socket, &remove), vec![wire::SSH_AGENT_SUCCESS]);
    assert_eq!(identity_blobs(&h), vec![cert.clone()]);

    assert_eq!(
        roundtrip(&h.socket, &sign_body(&cert, b"data")),
        vec![wire::SSH_AGENT_FAILURE]
    );
    h.sink.2.lock().unwrap().push_back(true);
    let reply = roundtrip(&h.socket, &sign_body(&cert, b"data"));
    assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);
}
