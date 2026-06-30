//! **Variant 4 — secp256k1 signing (both directions), symmetric.**
//!
//! Alternative to `bwc_basic`, for when your identity must be a secp256k1
//! signing key (e.g. a Bitcoin/Nostr key). Identical in structure to the
//! ed25519 signing variant; only the identity signature scheme differs
//! (secp256k1 ECDSA over a SHA-256 transcript — the standard Bitcoin curve).
//! HPKE base mode (X25519 KEM) provides confidentiality and the signatures
//! provide authentication.
//!
//! Out of band, the client pins the server's secp256k1 identity key and its
//! X25519 key; the server allowlists the client's secp256k1 identity key.
//!
//! Run with:
//! ```text
//! $ cargo run --example secp256k1_signing
//! ```

use std::collections::HashSet;

use anyhow::{anyhow, bail};

use hpke_base::{EncappedKey, PrivateKey, PublicKey};

fn main() -> anyhow::Result<()> {
    // --- Out-of-band setup --- //
    // The server has a secp256k1 identity (for signing replies) and an X25519
    // KEM key (for receiving requests); the client pins both. The client has a
    // secp256k1 identity, allowlisted by the server.
    let (server_sk, server_pk) = hpke_base::gen_keypair();
    let (client_id, client_id_pk) = identity::keypair();
    let (server_id, server_id_pk) = identity::keypair();

    let server = Server {
        sk: server_sk,
        id: server_id,
        allowlist: HashSet::from([client_id_pk.serialize()]),
    };
    let client = Client { id: client_id, server_pk, server_id: server_id_pk };
    println!("setup: server allowlisted one secp256k1 client identity");

    // --- Happy path --- //

    // Client signs + seals the request, with a fresh reply key for the answer.
    let (reply_sk, reply_pk) = hpke_base::gen_keypair();
    let (enc, ct) = client.frame_request(&reply_pk, b"hello");
    println!("client -> server: signed + sealed \"hello\"");

    // Server authenticates the client's signature and recovers the request.
    let (client_reply_pk, body) = server.open_request(&enc, &ct)?;
    println!("server: client signature verified, request = {:?}", String::from_utf8_lossy(&body));

    // Server signs + seals the reply; the client verifies the server signature.
    let (resp_enc, resp_ct) = server.frame_response(&client_reply_pk, b"goodbye");
    let response =
        client.open_response(&reply_sk, &hpke_base::pk_bytes(&reply_pk), &resp_enc, &resp_ct)?;
    println!("client: server signature verified, response = {:?}", String::from_utf8_lossy(&response));

    // --- Rejected: a client not on the allowlist --- //
    let stranger = Client {
        id: identity::keypair().0,
        server_pk: client.server_pk.clone(),
        server_id: client.server_id,
    };
    let (enc, ct) = stranger.frame_request(&reply_pk, b"hello");
    match server.open_request(&enc, &ct) {
        Ok(_) => bail!("a stranger's request should have been rejected"),
        Err(e) => println!("server: rejected unknown client ({e})"),
    }

    // --- Rejected: impersonating an allowlisted client --- //
    // The attacker knows the victim's public key but can't forge its signature.
    let attacker = identity::keypair().0;
    let reply_pk_bytes = hpke_base::pk_bytes(&reply_pk);
    let mut forged = identity::verifying_key(&client.id).serialize().to_vec();
    forged.extend_from_slice(&identity::sign(&attacker, &identity::request_transcript(&reply_pk_bytes, b"hello")));
    forged.extend_from_slice(&reply_pk_bytes);
    forged.extend_from_slice(b"hello");
    let (enc, ct) = hpke_base::seal(&client.server_pk, hpke_base::INFO_REQUEST, &forged);
    match server.open_request(&enc, &ct) {
        Ok(_) => bail!("an impersonated request should have been rejected"),
        Err(e) => println!("server: rejected impersonation ({e})"),
    }

    println!("\nok");
    Ok(())
}

/// The client: a secp256k1 signing identity that pins the server's KEM key (to
/// seal requests to) and identity key (to verify replies).
struct Client {
    id: identity::SigningKey,
    server_pk: PublicKey,
    server_id: identity::VerifyingKey,
}

impl Client {
    /// Sign `reply_pk || body`, then base-seal `id || sig || reply_pk || body`
    /// to the server (base mode hides the client's identity from the relay).
    fn frame_request(&self, reply_pk: &PublicKey, body: &[u8]) -> (EncappedKey, Vec<u8>) {
        let reply_pk_bytes = hpke_base::pk_bytes(reply_pk);
        let sig = identity::sign(&self.id, &identity::request_transcript(&reply_pk_bytes, body));
        let mut payload = Vec::new();
        payload.extend_from_slice(&identity::verifying_key(&self.id).serialize());
        payload.extend_from_slice(&sig);
        payload.extend_from_slice(&reply_pk_bytes);
        payload.extend_from_slice(body);
        hpke_base::seal(&self.server_pk, hpke_base::INFO_REQUEST, &payload)
    }

    /// Open the reply and verify the server's signature against its pinned key.
    fn open_response(
        &self,
        reply_sk: &PrivateKey,
        reply_pk_bytes: &[u8; hpke_base::PUBLIC_KEY_LEN],
        enc: &EncappedKey,
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let payload = hpke_base::open(reply_sk, hpke_base::INFO_RESPONSE, enc, ciphertext)?;
        if payload.len() < identity::SIG_LEN {
            bail!("malformed response");
        }
        let (sig, body) = payload.split_at(identity::SIG_LEN);
        if !identity::verify(&self.server_id, &identity::response_transcript(reply_pk_bytes, body), sig) {
            bail!("bad server signature");
        }
        Ok(body.to_vec())
    }
}

/// The server: an X25519 KEM key for receiving, a secp256k1 identity for signing
/// replies, and an allowlist of client identities.
struct Server {
    sk: PrivateKey,
    id: identity::SigningKey,
    allowlist: HashSet<[u8; identity::PK_LEN]>,
}

impl Server {
    /// Open + verify a request, returning the client's reply key and body.
    fn open_request(&self, enc: &EncappedKey, ciphertext: &[u8]) -> anyhow::Result<(PublicKey, Vec<u8>)> {
        let payload = hpke_base::open(&self.sk, hpke_base::INFO_REQUEST, enc, ciphertext)?;

        const MIN_LEN: usize = identity::PK_LEN + identity::SIG_LEN + hpke_base::PUBLIC_KEY_LEN;
        if payload.len() < MIN_LEN {
            bail!("malformed request");
        }
        let (id, rest) = payload.split_at(identity::PK_LEN);
        let (sig, rest) = rest.split_at(identity::SIG_LEN);
        let (reply_pk_bytes, body) = rest.split_at(hpke_base::PUBLIC_KEY_LEN);
        let id: [u8; identity::PK_LEN] = id.try_into().expect("len checked");

        if !self.allowlist.contains(&id) {
            bail!("unauthorized: client not on allowlist");
        }
        let client_id = identity::VerifyingKey::from_slice(&id).map_err(|e| anyhow!("bad client key: {e}"))?;
        if !identity::verify(&client_id, &identity::request_transcript(reply_pk_bytes, body), sig) {
            bail!("bad client signature");
        }

        Ok((hpke_base::pk_from_bytes(reply_pk_bytes)?, body.to_vec()))
    }

    /// Sign `reply_pk || body`, then base-seal `sig || body` to the client's
    /// reply key. The client already knows the server's identity key.
    fn frame_response(&self, reply_pk: &PublicKey, body: &[u8]) -> (EncappedKey, Vec<u8>) {
        let reply_pk_bytes = hpke_base::pk_bytes(reply_pk);
        let sig = identity::sign(&self.id, &identity::response_transcript(&reply_pk_bytes, body));
        let mut payload = Vec::new();
        payload.extend_from_slice(&sig);
        payload.extend_from_slice(body);
        hpke_base::seal(reply_pk, hpke_base::INFO_RESPONSE, &payload)
    }
}

/// The identity scheme: a secp256k1 signing key (ECDSA over a SHA-256
/// transcript — the standard Bitcoin curve). A fresh `Secp256k1` context per
/// call keeps this a leaf utility; reuse one in a real deployment.
mod identity {
    use hpke_demo::rng::random_bytes;
    use secp256k1::{Message, Secp256k1, ecdsa::Signature};
    use sha2::{Digest, Sha256};

    pub use secp256k1::{PublicKey as VerifyingKey, SecretKey as SigningKey};

    pub const PK_LEN: usize = 33;
    pub const SIG_LEN: usize = 64;

    const REQUEST_DOMAIN: &[u8] = b"hpke-demo secp256k1 request";
    const RESPONSE_DOMAIN: &[u8] = b"hpke-demo secp256k1 response";

    pub fn keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_byte_array(random_bytes::<32>())
            .expect("32 random bytes are a valid secp256k1 key");
        let pk = VerifyingKey::from_secret_key(&Secp256k1::new(), &sk);
        (sk, pk)
    }

    pub fn verifying_key(sk: &SigningKey) -> VerifyingKey {
        VerifyingKey::from_secret_key(&Secp256k1::new(), sk)
    }

    pub fn request_transcript(reply_pk_bytes: &[u8], body: &[u8]) -> Vec<u8> {
        [REQUEST_DOMAIN, reply_pk_bytes, body].concat()
    }

    pub fn response_transcript(reply_pk_bytes: &[u8], body: &[u8]) -> Vec<u8> {
        [RESPONSE_DOMAIN, reply_pk_bytes, body].concat()
    }

    pub fn sign(sk: &SigningKey, transcript: &[u8]) -> [u8; SIG_LEN] {
        let msg = Message::from_digest(sha256(transcript));
        Secp256k1::new().sign_ecdsa(msg, sk).serialize_compact()
    }

    pub fn verify(pk: &VerifyingKey, transcript: &[u8], sig: &[u8]) -> bool {
        let Ok(sig) = Signature::from_compact(sig) else {
            return false;
        };
        let msg = Message::from_digest(sha256(transcript));
        Secp256k1::new().verify_ecdsa(msg, &sig, pk).is_ok()
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(data));
        out
    }
}

/// HPKE base mode, for confidentiality only. Suite: X25519 KEM, HKDF-SHA256,
/// ChaCha20Poly1305.
mod hpke_base {
    use anyhow::anyhow;
    use hpke::{
        Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
        aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver,
        setup_sender,
    };
    use hpke_demo::rng::OsRng;

    type Kem = X25519HkdfSha256;
    type Kdf = HkdfSha256;
    type Aead = ChaCha20Poly1305;

    pub type PublicKey = <Kem as KemTrait>::PublicKey;
    pub type PrivateKey = <Kem as KemTrait>::PrivateKey;
    pub type EncappedKey = <Kem as KemTrait>::EncappedKey;

    /// Length of a serialized X25519 KEM public key.
    pub const PUBLIC_KEY_LEN: usize = 32;
    /// HPKE `info` strings binding each direction to this protocol.
    pub const INFO_REQUEST: &[u8] = b"hpke-demo request";
    pub const INFO_RESPONSE: &[u8] = b"hpke-demo response";

    pub fn gen_keypair() -> (PrivateKey, PublicKey) {
        Kem::gen_keypair(&mut OsRng)
    }

    pub fn pk_bytes(pk: &PublicKey) -> [u8; PUBLIC_KEY_LEN] {
        let mut out = [0u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(pk.to_bytes().as_slice());
        out
    }

    pub fn pk_from_bytes(bytes: &[u8]) -> anyhow::Result<PublicKey> {
        PublicKey::from_bytes(bytes).map_err(|e| anyhow!("malformed KEM public key: {e:?}"))
    }

    /// Base mode: seal `plaintext` to `recipient_pk` (anonymous sender).
    pub fn seal(recipient_pk: &PublicKey, info: &[u8], plaintext: &[u8]) -> (EncappedKey, Vec<u8>) {
        let (enc, mut ctx) =
            setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, recipient_pk, info, &mut OsRng)
                .expect("sender setup");
        let ciphertext = ctx.seal(plaintext, b"").expect("seal");
        (enc, ciphertext)
    }

    /// Base mode: open a message sealed to `recipient_sk`.
    pub fn open(
        recipient_sk: &PrivateKey,
        info: &[u8],
        enc: &EncappedKey,
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut ctx = setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, recipient_sk, enc, info)
            .map_err(|e| anyhow!("receiver setup: {e:?}"))?;
        ctx.open(ciphertext, b"").map_err(|e| anyhow!("decrypt: {e:?}"))
    }
}
