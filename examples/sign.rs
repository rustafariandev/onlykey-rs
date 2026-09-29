//! Sign stdin with a derived key and print the signature blob as base64,
//! after the user confirms the challenge on the device.
//!
//! ```sh
//! echo -n hello | cargo run --example sign -- ferris@example.com
//! ```

use onlykey_agent::challenge::TtyPrompt;
use onlykey_agent::ssh_key::HashAlg;
use onlykey_agent::{Curve, KeySpec, OnlyKey};
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = std::env::args()
        .nth(1)
        .ok_or("usage: sign <[user@]host> < data")?
        .parse()?;
    let spec = KeySpec::derived(identity, Curve::Ed25519);
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data)?;

    let mut device = OnlyKey::open()?;
    let key = device.ssh_public_key(&spec)?;
    let sig = device.ssh_sign(
        &spec,
        &key,
        &data,
        HashAlg::Sha512,
        Some("example".into()),
        &TtyPrompt,
    )?;
    println!("{}", key.to_openssh()?);
    println!("{} {}", sig.algorithm(), hex::encode(sig.as_bytes()));
    Ok(())
}
