//! **Variant 3 — ed25519 signing (both directions), symmetric.**
//!
//! Alternative to `bwc_basic`, for when your identity must be an ed25519
//! signing key rather than an X25519 KEM key. Both the client and server are
//! identified by a long-lived ed25519 signing key (via [`ring`]); each *signs*
//! its messages and the peer verifies. HPKE is
//! used in base mode purely for confidentiality (X25519 KEM), and the
//! signatures provide authentication — so the identities are ed25519 keys
//! rather than KEM keys. This is the NIP-47-style design.
//!
//! Out of band, the client pins the server's ed25519 identity key (to verify
//! replies) and the server's X25519 key (to encrypt requests to); the server
//! allowlists the client's ed25519 identity key.
//!
//! Run with:
//! ```text
//! $ cargo run --example ed25519_signing
//! ```

use std::collections::HashSet;

use anyhow::bail;

use hpke_base::{EncappedKey, PrivateKey, PublicKey};
use identity::Ed25519KeyPair;

fn main() -> anyhow::Result<()> {
    // --- Out-of-band setup --- //
    // The server has an ed25519 identity (for signing replies) and an X25519
    // KEM key (for receiving requests); the client pins both. The client has an
    // ed25519 identity, allowlisted by the server.
    let (server_sk, server_pk) = hpke_base::gen_keypair();
    let client_id = identity::keypair();
    let server = Server {
        sk: server_sk,
        id: identity::keypair(),
        allowlist: HashSet::from([identity::pubkey(&client_id)]),
    };
    let client = Client {
        id: client_id,
        server_pk,
        server_id: identity::pubkey(&server.id),
    };
    println!("setup: server allowlisted one ed25519 client identity");

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
        id: identity::keypair(),
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
    let attacker = identity::keypair();
    let reply_pk_bytes = hpke_base::pk_bytes(&reply_pk);
    let mut forged = identity::pubkey(&client.id).to_vec();
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

/// The client: an ed25519 signing identity that pins the server's KEM key (to
/// seal requests to) and identity key (to verify replies).
struct Client {
    id: Ed25519KeyPair,
    server_pk: PublicKey,
    server_id: [u8; identity::PK_LEN],
}

impl Client {
    /// Sign `reply_pk || body`, then base-seal `id || sig || reply_pk || body`
    /// to the server (base mode hides the client's identity from the relay).
    fn frame_request(&self, reply_pk: &PublicKey, body: &[u8]) -> (EncappedKey, Vec<u8>) {
        let reply_pk_bytes = hpke_base::pk_bytes(reply_pk);
        let sig = identity::sign(&self.id, &identity::request_transcript(&reply_pk_bytes, body));
        let mut payload = Vec::new();
        payload.extend_from_slice(&identity::pubkey(&self.id));
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

/// The server: an X25519 KEM key for receiving, an ed25519 identity for signing
/// replies, and an allowlist of client identities.
struct Server {
    sk: PrivateKey,
    id: Ed25519KeyPair,
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
        if !identity::verify(&id, &identity::request_transcript(reply_pk_bytes, body), sig) {
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

/// The identity scheme: a long-lived ed25519 signing key (via `ring`).
mod identity {
    use hpke_demo::rng::random_bytes;
    use ring::signature::{self, KeyPair, UnparsedPublicKey};

    pub use ring::signature::Ed25519KeyPair;

    pub const PK_LEN: usize = 32;
    pub const SIG_LEN: usize = 64;

    const REQUEST_DOMAIN: &[u8] = b"hpke-demo ed25519 request";
    const RESPONSE_DOMAIN: &[u8] = b"hpke-demo ed25519 response";

    pub fn keypair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&random_bytes::<32>())
            .expect("a 32-byte seed is always valid")
    }

    pub fn pubkey(kp: &Ed25519KeyPair) -> [u8; PK_LEN] {
        kp.public_key().as_ref().try_into().expect("ed25519 public key is 32 bytes")
    }

    pub fn request_transcript(reply_pk_bytes: &[u8], body: &[u8]) -> Vec<u8> {
        [REQUEST_DOMAIN, reply_pk_bytes, body].concat()
    }

    pub fn response_transcript(reply_pk_bytes: &[u8], body: &[u8]) -> Vec<u8> {
        [RESPONSE_DOMAIN, reply_pk_bytes, body].concat()
    }

    pub fn sign(kp: &Ed25519KeyPair, transcript: &[u8]) -> [u8; SIG_LEN] {
        kp.sign(transcript).as_ref().try_into().expect("ed25519 signature is 64 bytes")
    }

    pub fn verify(id: &[u8], transcript: &[u8], sig: &[u8]) -> bool {
        UnparsedPublicKey::new(&signature::ED25519, id).verify(transcript, sig).is_ok()
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
