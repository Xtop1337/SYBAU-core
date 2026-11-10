//! Key exchange groups offered in the ClientHello.

use std::io;

use ml_kem::kem::Decapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use sybau_common::proto_err;

pub const GROUP_SECP256R1: u16 = 0x0017;
pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_X25519_MLKEM768: u16 = 0x11ec;

const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;

type MlKemDecapsulationKey = <MlKem768 as KemCore>::DecapsulationKey;

/// Private halves of everything sent in the `key_share` extension.
///
/// The X25519 key is shared between the plain and the hybrid share, as in
/// Go's TLS stack; REALITY derives its authentication key from it.
pub struct KeyShares {
    pub x25519: x25519_dalek::StaticSecret,
    p256: Option<p256::ecdh::EphemeralSecret>,
    mlkem: Option<Box<MlKemDecapsulationKey>>,
}

impl KeyShares {
    pub fn new() -> Self {
        Self {
            x25519: x25519_dalek::StaticSecret::random_from_rng(OsRng),
            p256: None,
            mlkem: None,
        }
    }

    pub fn can_offer(group: u16) -> bool {
        matches!(
            group,
            GROUP_SECP256R1 | GROUP_X25519 | GROUP_X25519_MLKEM768
        )
    }

    /// Public value to put into the `key_share` entry of `group`.
    pub fn public(&mut self, group: u16) -> Option<Vec<u8>> {
        match group {
            GROUP_X25519 => Some(
                x25519_dalek::PublicKey::from(&self.x25519)
                    .as_bytes()
                    .to_vec(),
            ),
            GROUP_SECP256R1 => {
                let secret = self
                    .p256
                    .get_or_insert_with(|| p256::ecdh::EphemeralSecret::random(&mut OsRng));
                Some(
                    p256::EncodedPoint::from(secret.public_key())
                        .as_bytes()
                        .to_vec(),
                )
            }
            GROUP_X25519_MLKEM768 => {
                if self.mlkem.is_none() {
                    let (dk, _ek) = MlKem768::generate(&mut OsRng);
                    self.mlkem = Some(Box::new(dk));
                }
                let dk = self.mlkem.as_ref().expect("generated above");
                let mut out = Vec::with_capacity(MLKEM768_EK_LEN + 32);
                out.extend_from_slice(&dk.encapsulation_key().as_bytes());
                out.extend_from_slice(x25519_dalek::PublicKey::from(&self.x25519).as_bytes());
                Some(out)
            }
            _ => None,
        }
    }

    /// Computes the shared secret from the server's `key_share`.
    pub fn shared_secret(&self, group: u16, server_share: &[u8]) -> io::Result<Vec<u8>> {
        let x25519 = |peer: &[u8]| -> io::Result<[u8; 32]> {
            let peer: [u8; 32] = peer
                .try_into()
                .map_err(|_| proto_err("bad X25519 key share length"))?;
            let shared = self
                .x25519
                .diffie_hellman(&x25519_dalek::PublicKey::from(peer));
            if !shared.was_contributory() {
                return Err(proto_err("server sent a low-order X25519 point"));
            }
            Ok(*shared.as_bytes())
        };
        match group {
            GROUP_X25519 => Ok(x25519(server_share)?.to_vec()),
            GROUP_SECP256R1 => {
                let secret = self
                    .p256
                    .as_ref()
                    .ok_or_else(|| proto_err("server chose a group that was not offered"))?;
                let peer = p256::PublicKey::from_sec1_bytes(server_share)
                    .map_err(|_| proto_err("bad P-256 key share"))?;
                Ok(secret.diffie_hellman(&peer).raw_secret_bytes().to_vec())
            }
            GROUP_X25519_MLKEM768 => {
                let dk = self
                    .mlkem
                    .as_ref()
                    .ok_or_else(|| proto_err("server chose a group that was not offered"))?;
                if server_share.len() != MLKEM768_CT_LEN + 32 {
                    return Err(proto_err("bad X25519MLKEM768 key share length"));
                }
                let ct = ml_kem::Ciphertext::<MlKem768>::try_from(&server_share[..MLKEM768_CT_LEN])
                    .map_err(|_| proto_err("bad ML-KEM ciphertext"))?;
                let kem_secret = dk
                    .decapsulate(&ct)
                    .map_err(|_| proto_err("ML-KEM decapsulation failed"))?;
                let mut out = Vec::with_capacity(64);
                out.extend_from_slice(&kem_secret);
                out.extend_from_slice(&x25519(&server_share[MLKEM768_CT_LEN..])?);
                Ok(out)
            }
            other => Err(proto_err(format!(
                "server chose unsupported group {other:#06x}"
            ))),
        }
    }
}

impl Default for KeyShares {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::kem::Encapsulate;

    #[test]
    fn x25519_and_p256_agree_with_a_peer() {
        let mut client = KeyShares::new();
        let mut server = KeyShares::new();
        for group in [GROUP_X25519, GROUP_SECP256R1] {
            let c_pub = client.public(group).unwrap();
            let s_pub = server.public(group).unwrap();
            assert_eq!(
                client.shared_secret(group, &s_pub).unwrap(),
                server.shared_secret(group, &c_pub).unwrap()
            );
        }
        assert_eq!(client.public(GROUP_SECP256R1).unwrap().len(), 65);
        assert!(
            client.shared_secret(GROUP_X25519, &[0u8; 32]).is_err(),
            "low-order point must be rejected"
        );
        assert!(client.shared_secret(GROUP_X25519, &[1u8; 31]).is_err());
    }

    #[test]
    fn hybrid_share_layout_and_secret() {
        let mut client = KeyShares::new();
        let share = client.public(GROUP_X25519_MLKEM768).unwrap();
        assert_eq!(share.len(), MLKEM768_EK_LEN + 32);
        // The X25519 half equals the standalone X25519 share.
        assert_eq!(
            &share[MLKEM768_EK_LEN..],
            &client.public(GROUP_X25519).unwrap()[..]
        );

        // Server side of the hybrid exchange.
        let ek_bytes = ml_kem::Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(
            &share[..MLKEM768_EK_LEN],
        )
        .unwrap();
        let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_bytes);
        let (ct, kem_secret) = ek.encapsulate(&mut OsRng).unwrap();
        let server_x = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let mut server_share = ct.to_vec();
        server_share.extend_from_slice(x25519_dalek::PublicKey::from(&server_x).as_bytes());
        let peer: [u8; 32] = share[MLKEM768_EK_LEN..].try_into().unwrap();
        let mut expect = kem_secret.to_vec();
        expect.extend_from_slice(
            server_x
                .diffie_hellman(&x25519_dalek::PublicKey::from(peer))
                .as_bytes(),
        );

        assert_eq!(
            client
                .shared_secret(GROUP_X25519_MLKEM768, &server_share)
                .unwrap(),
            expect
        );
        assert!(client
            .shared_secret(GROUP_X25519_MLKEM768, &server_share[1..])
            .is_err());
    }
}
