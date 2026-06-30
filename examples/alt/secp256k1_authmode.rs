//! **Variant 2 — native secp256k1, HPKE auth mode (both directions).**
//!
//! **Alternative to `bwc_basic`; not recommended.** Use this only if your
//! identity must be a secp256k1 *KEM* key. Like the X25519 auth-mode baseline,
//! but the KEM curve is secp256k1, so the client and server identities *are*
//! their HPKE KEM keys — no signatures. secp256k1 is not a standard HPKE KEM
//! (not in RFC 9180), so this requires a non-standard DHKEM (`DhK256HkdfSha256`)
//! from the `rust-hpke-secp` fork, pulled in as a git dep. If you have a
//! secp256k1 identity, prefer `secp256k1_signing` instead.
//!
//! Auth mode needs the recipient to know the sender's public key *before*
//! decrypting, so the client's identity is sent in the clear (unlike the
//! signing variants, which hide it inside the ciphertext).
//!
//! Run with:
//! ```text
//! $ cargo run --example secp256k1_authmode
//! ```

use std::collections::HashSet;

use anyhow::{anyhow, bail};

use hpke_auth::{EncappedKey, PrivateKey, PublicKey};

fn main() -> anyhow::Result<()> {
    // --- Out-of-band setup --- //
    // Both parties are identified by a secp256k1 KEM keypair; the server
    // allowlists the client's identity.
    let (server_sk, server_pk) = hpke_auth::gen_keypair();
    let (client_sk, client_pk) = hpke_auth::gen_keypair();
    let server = Server {
        sk: server_sk,
        pk: server_pk.clone(),
        allowlist: HashSet::from([hpke_auth::pk_bytes(&client_pk)]),
    };
    let client = Client { sk: client_sk, pk: client_pk, server_pk };
    println!("setup: server allowlisted one secp256k1 client identity");

    // --- Happy path --- //

    // Client auth-seals the request with its identity key; the claimed identity
    // travels in the clear so the server can pick the key to verify against.
    let (enc, ct) = client.seal_request(b"hello");
    println!("client -> server: auth-sealed \"hello\" (identity sent in the clear)");

    let body = server.handle(&client.identity(), &enc, &ct)?;
    println!("server: client authenticated, request = {:?}", String::from_utf8_lossy(&body));

    // Server auth-seals the reply with its identity key; the client verifies it.
    let (resp_enc, resp_ct) = server.seal_response(&client.pk, b"goodbye");
    let response = client.open_response(&resp_enc, &resp_ct)?;
    println!("client: reply verified from server, response = {:?}", String::from_utf8_lossy(&response));

    // --- Rejected: a client not on the allowlist --- //
    let (stranger_sk, stranger_pk) = hpke_auth::gen_keypair();
    let stranger = Client { sk: stranger_sk, pk: stranger_pk, server_pk: client.server_pk.clone() };
    let (enc, ct) = stranger.seal_request(b"hello");
    match server.handle(&stranger.identity(), &enc, &ct) {
        Ok(_) => bail!("a stranger's request should have been rejected"),
        Err(e) => println!("server: rejected unknown client ({e})"),
    }

    // --- Rejected: impersonating an allowlisted client --- //
    // The attacker claims the victim's identity but seals with its own key, so
    // the server's auth-mode decapsulation fails.
    let (attacker_sk, attacker_pk) = hpke_auth::gen_keypair();
    let attacker = Client { sk: attacker_sk, pk: attacker_pk, server_pk: client.server_pk.clone() };
    let (enc, ct) = attacker.seal_request(b"hello");
    match server.handle(&client.identity(), &enc, &ct) {
        Ok(_) => bail!("an impersonated request should have been rejected"),
        Err(e) => println!("server: rejected impersonation ({e})"),
    }

    println!("\nok");
    Ok(())
}

/// The client: a secp256k1 KEM keypair (its identity) that pins the server's key.
struct Client {
    sk: PrivateKey,
    pk: PublicKey,
    server_pk: PublicKey,
}

impl Client {
    /// The client's identity: its KEM public key, sent in the clear so the
    /// server knows which key to verify the request against.
    fn identity(&self) -> Vec<u8> {
        hpke_auth::pk_bytes(&self.pk)
    }

    /// Auth-seal a request to the server, authenticating with the client's key.
    fn seal_request(&self, plaintext: &[u8]) -> (EncappedKey, Vec<u8>) {
        hpke_auth::seal((self.sk.clone(), self.pk.clone()), &self.server_pk, hpke_auth::INFO_REQUEST, plaintext)
    }

    /// Auth-open the server's reply, verifying it came from the pinned server key.
    fn open_response(&self, enc: &EncappedKey, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        hpke_auth::open(&self.sk, &self.server_pk, hpke_auth::INFO_RESPONSE, enc, ciphertext)
    }
}

/// The server: a secp256k1 KEM keypair (its identity) and a client allowlist.
struct Server {
    sk: PrivateKey,
    pk: PublicKey,
    allowlist: HashSet<Vec<u8>>,
}

impl Server {
    /// Check the claimed identity is allowlisted, then auth-open the request
    /// (which only succeeds if the sender actually holds that identity).
    fn handle(&self, claimed_id: &[u8], enc: &EncappedKey, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        if !self.allowlist.contains(claimed_id) {
            bail!("unauthorized: client not on allowlist");
        }
        let client_pk = hpke_auth::pk_from_bytes(claimed_id)?;
        hpke_auth::open(&self.sk, &client_pk, hpke_auth::INFO_REQUEST, enc, ciphertext)
            .map_err(|_| anyhow!("authentication failed"))
    }

    /// Auth-seal a reply to `client_pk`, authenticating with the server's key.
    fn seal_response(&self, client_pk: &PublicKey, plaintext: &[u8]) -> (EncappedKey, Vec<u8>) {
        hpke_auth::seal((self.sk.clone(), self.pk.clone()), client_pk, hpke_auth::INFO_RESPONSE, plaintext)
    }
}

/// HPKE auth mode over a non-standard secp256k1 KEM (the `rust-hpke-secp` fork).
/// Suite: DhK256HkdfSha256 KEM, HKDF-SHA256, ChaCha20Poly1305.
mod hpke_auth {
    use anyhow::anyhow;
    use hpke_secp::{
        Deserializable, OpModeR, OpModeS, Serializable,
        aead::ChaCha20Poly1305,
        kdf::HkdfSha256,
        kem::{DhK256HkdfSha256, Kem as KemTrait},
        rand_core::{CryptoRng, RngCore},
        setup_receiver, setup_sender,
    };

    type Kem = DhK256HkdfSha256;
    type Kdf = HkdfSha256;
    type Aead = ChaCha20Poly1305;

    pub type PublicKey = <Kem as KemTrait>::PublicKey;
    pub type PrivateKey = <Kem as KemTrait>::PrivateKey;
    pub type EncappedKey = <Kem as KemTrait>::EncappedKey;

    pub const INFO_REQUEST: &[u8] = b"hpke-demo secp256k1-authmode request";
    pub const INFO_RESPONSE: &[u8] = b"hpke-demo secp256k1-authmode response";

    pub fn gen_keypair() -> (PrivateKey, PublicKey) {
        Kem::gen_keypair(&mut OsRng)
    }

    pub fn pk_bytes(pk: &PublicKey) -> Vec<u8> {
        pk.to_bytes().to_vec()
    }

    pub fn pk_from_bytes(bytes: &[u8]) -> anyhow::Result<PublicKey> {
        PublicKey::from_bytes(bytes).map_err(|e| anyhow!("bad pubkey: {e:?}"))
    }

    /// Auth-seal `plaintext` to `recipient_pk`, authenticating with `sender_kp`.
    pub fn seal(
        sender_kp: (PrivateKey, PublicKey),
        recipient_pk: &PublicKey,
        info: &[u8],
        plaintext: &[u8],
    ) -> (EncappedKey, Vec<u8>) {
        let (enc, mut ctx) =
            setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Auth(sender_kp), recipient_pk, info, &mut OsRng)
                .expect("sender setup");
        let ciphertext = ctx.seal(plaintext, b"").expect("seal");
        (enc, ciphertext)
    }

    /// Auth-open a message, verifying via auth mode that it came from `sender_pk`.
    pub fn open(
        recipient_sk: &PrivateKey,
        sender_pk: &PublicKey,
        info: &[u8],
        enc: &EncappedKey,
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut ctx =
            setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Auth(sender_pk.clone()), recipient_sk, enc, info)
                .map_err(|e| anyhow!("receiver setup: {e:?}"))?;
        ctx.open(ciphertext, b"").map_err(|e| anyhow!("decrypt: {e:?}"))
    }

    /// An OS-seeded CSPRNG implementing the fork's `rand_core` 0.6 traits.
    struct OsRng;

    impl CryptoRng for OsRng {}

    impl RngCore for OsRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }

        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            getrandom::fill(dst).expect("OS RNG failure");
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), hpke_secp::rand_core::Error> {
            self.fill_bytes(dst);
            Ok(())
        }
    }
}
