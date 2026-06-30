//! The BWC v1 sealing layer: X25519 HPKE in AuthPSK mode.
//!
//! Each request/response is a one-shot HPKE context. The sender authenticates
//! two ways at once (AuthPSK): the connection `secret` is the PSK, and the
//! sender's X25519 static key is bound into the KEM. Suite: DHKEM(X25519,
//! HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305.
//!
//! [`seal`] returns the wire bytes `enc || ciphertext`; [`open`] takes them back.

use anyhow::{anyhow, bail};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, PskBundle, Serializable,
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver,
    setup_sender,
};

use crate::rng::OsRng;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

pub type PublicKey = <Kem as KemTrait>::PublicKey;
pub type PrivateKey = <Kem as KemTrait>::PrivateKey;
type EncappedKey = <Kem as KemTrait>::EncappedKey;

/// Length of a serialized X25519 KEM public key (and encapsulated key).
pub const KEM_PUBLIC_KEY_LEN: usize = 32;

/// PSK identifier paired with the connection secret (HPKE wants a non-empty pair).
const PSK_ID: &[u8] = b"bwc-connection";

/// Generate a fresh X25519 KEM keypair.
pub fn gen_keypair() -> (PrivateKey, PublicKey) {
    Kem::gen_keypair(&mut OsRng)
}

/// Serialize a KEM public key to its 32-byte encoding.
pub fn kem_pk_bytes(pk: &PublicKey) -> [u8; KEM_PUBLIC_KEY_LEN] {
    let mut out = [0u8; KEM_PUBLIC_KEY_LEN];
    out.copy_from_slice(pk.to_bytes().as_slice());
    out
}

/// Deserialize a KEM public key from its 32-byte encoding.
pub fn kem_pk_from_bytes(bytes: &[u8]) -> anyhow::Result<PublicKey> {
    PublicKey::from_bytes(bytes).map_err(|e| anyhow!("malformed KEM public key: {e:?}"))
}

/// AuthPSK-seal `plaintext` to `recipient_pk`, authenticating as `sender` under
/// the connection `psk`. Returns the wire bytes `enc || ciphertext`.
pub fn seal(
    sender: (&PrivateKey, &PublicKey),
    recipient_pk: &PublicKey,
    psk: &[u8],
    info: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let bundle = PskBundle::new(psk, PSK_ID).expect("non-empty psk + psk_id");
    let mode = OpModeS::AuthPsk((sender.0.clone(), sender.1.clone()), bundle);
    let (enc, mut ctx) = setup_sender::<Aead, Kdf, Kem, _>(&mode, recipient_pk, info, &mut OsRng)
        .expect("sender setup");
    let ciphertext = ctx.seal(plaintext, b"").expect("seal");
    [enc.to_bytes().as_slice(), &ciphertext].concat()
}

/// Open a wire message (`enc || ciphertext`), verifying it came from `sender_pk`
/// under `psk`.
pub fn open(
    recipient_sk: &PrivateKey,
    sender_pk: &PublicKey,
    psk: &[u8],
    info: &[u8],
    wire: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if wire.len() < KEM_PUBLIC_KEY_LEN {
        bail!("message too short");
    }
    let (enc_bytes, ciphertext) = wire.split_at(KEM_PUBLIC_KEY_LEN);
    let enc = EncappedKey::from_bytes(enc_bytes).map_err(|e| anyhow!("malformed enc: {e:?}"))?;

    let bundle = PskBundle::new(psk, PSK_ID).map_err(|e| anyhow!("psk bundle: {e:?}"))?;
    let mode = OpModeR::AuthPsk(sender_pk.clone(), bundle);
    let mut ctx = setup_receiver::<Aead, Kdf, Kem>(&mode, recipient_sk, &enc, info)
        .map_err(|e| anyhow!("receiver setup: {e:?}"))?;
    ctx.open(ciphertext, b"").map_err(|_| anyhow!("authentication/decryption failed"))
}
