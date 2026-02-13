use blake3::Hash;
use uuid::Uuid;

pub fn derive_overlay_prefixes(network_id: &Uuid) -> (String, String) {
    let hash = blake3::hash(network_id.as_bytes());
    let v6 = derive_ipv6_ula(&hash);
    let v4 = derive_ipv4_overlay(&hash);
    (v4, v6)
}

fn derive_ipv6_ula(hash: &Hash) -> String {
    let bytes = hash.as_bytes();
    let b0 = bytes[0];
    let b1 = bytes[1];
    let b2 = bytes[2];
    let b3 = bytes[3];
    let b4 = bytes[4];
    format!(
        "fd{:02x}:{:02x}{:02x}:{:02x}{:02x}::/48",
        b0, b1, b2, b3, b4
    )
}

fn derive_ipv4_overlay(hash: &Hash) -> String {
    let bytes = hash.as_bytes();
    let raw = u16::from_be_bytes([bytes[5], bytes[6]]);
    let idx = raw & 0x3fff;
    let second = 64 + ((idx >> 8) as u8);
    let third = (idx & 0xff) as u8;
    format!("100.{}.{}.0/24", second, third)
}
