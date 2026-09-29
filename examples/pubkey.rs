//! Print the authorized_keys line for an identity, derived or from a stored
//! slot.
//!
//! ```sh
//! cargo run --example pubkey -- ferris@example.com [ed25519|nistp256] [ECC3|RSA1]
//! ```

use onlykey_agent::{Curve, KeyKind, KeySpec, OnlyKey, Slot};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let identity = args
        .next()
        .ok_or("usage: pubkey <[user@]host> [curve] [ECCn|RSAn]")?
        .parse()?;
    let curve: Curve = args.next().as_deref().unwrap_or("ed25519").parse()?;
    let kind = match args.next().map(|s| s.parse::<Slot>()).transpose()? {
        None => KeyKind::Derived(curve),
        Some(Slot::Ecc(slot)) => KeyKind::StoredEcc { slot, curve },
        Some(Slot::Rsa(slot)) => KeyKind::StoredRsa(slot),
    };
    let spec = KeySpec { identity, kind };

    let mut device = OnlyKey::open()?;
    eprintln!(
        "firmware {}",
        device.firmware_version().unwrap_or("(locked)")
    );
    let key = device.ssh_public_key(&spec)?;
    println!("{}", key.to_openssh()?);
    Ok(())
}
