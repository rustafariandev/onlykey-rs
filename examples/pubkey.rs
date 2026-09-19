//! Print the authorized_keys line for an identity.
//!
//! ```sh
//! cargo run --example pubkey -- james@example.com [ed25519|nistp256]
//! ```

use onlykey_agent::{Curve, Identity, OnlyKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let identity: Identity = args
        .next()
        .ok_or("usage: pubkey <[user@]host> [curve]")?
        .parse()?;
    let curve: Curve = args.next().as_deref().unwrap_or("ed25519").parse()?;

    let mut device = OnlyKey::open()?;
    eprintln!(
        "firmware {}",
        device.firmware_version().unwrap_or("(locked)")
    );
    let key = device.ssh_public_key(&identity, curve)?;
    println!("{}", key.to_openssh()?);
    Ok(())
}
