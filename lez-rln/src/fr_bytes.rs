//! 32-byte little-endian canonical encoding of BN254 scalar field elements —
//! the wire format for commitments, leaves, and roots shared with on-chain
//! state and the guest's Poseidon implementation.

use rln::prelude::{CanonicalDeserialize, CanonicalSerialize, Fr};

/// Serializes a field element to its 32-byte little-endian canonical form.
pub fn fr_to_bytes_le(fr: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fr.serialize_compressed(bytes.as_mut_slice())
        .expect("Fr canonical form is exactly 32 bytes");
    bytes
}

/// Parses a 32-byte little-endian value as a field element.
///
/// Returns `None` if the value is non-canonical (>= the BN254 scalar field
/// modulus); callers rely on this as a canonicity guard, never reduce.
pub fn bytes_le_to_fr(bytes: &[u8; 32]) -> Option<Fr> {
    Fr::deserialize_compressed(bytes.as_slice()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let fr = Fr::from(12_345_678_u64);
        let bytes = fr_to_bytes_le(&fr);
        assert_eq!(bytes_le_to_fr(&bytes), Some(fr));
    }

    #[test]
    fn rejects_non_canonical() {
        assert_eq!(bytes_le_to_fr(&[0xff; 32]), None);
    }
}
