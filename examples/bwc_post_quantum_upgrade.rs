//! **BWC connection-string versioning — a possible future post-quantum upgrade.**
//!
//! A wallet hands the client an NWC-style connection string carrying a `?v=`
//! version:
//!
//! ```text
//! bwc://<relay>?v=1&wallet_pk=<hex pubkey>&secret=<hex>
//! ```
//!
//! The client parses `v` and seals its request *accordingly*, so the crypto
//! suite can be upgraded — most importantly classical → post-quantum — by
//! issuing a new connection string, with no change to the client's code path or
//! the string format:
//!
//! - **v1** — X25519 HPKE in **AuthPSK** mode. The connection `secret` is the
//!   PSK, and the client's X25519 static key is additionally bound into the KEM.
//! - **v2** — **X-Wing** (X25519 + ML-KEM-768) post-quantum KEM in **PSK** mode.
//!   X-Wing has no authenticated-KEM variant, so the static-key binding drops
//!   and the connection `secret` (PSK) is the sole client authenticator. That's
//!   the point: authentication rides the PSK, not the KEM, so it survives the
//!   swap to a KEM that can't do Auth mode.
//!
//! X-Wing is not an HPKE KEM (RFC 9180 defines none — it's `draft-ietf-hpke-pq`),
//! so v2's tiny `encapsulate → HKDF-SHA256 → ChaCha20Poly1305` schedule is built
//! by hand (see [`v2`]) rather than via the `hpke` crate. Only the request
//! direction is shown; responses mirror it (see the other examples for full
//! round trips).
//!
//! Run with:
//! ```text
//! $ cargo run --example bwc_post_quantum_upgrade
//! ```

use anyhow::{anyhow, bail};
use hpke_demo::rng::random_bytes;

/// Cosmetic relay host (the mailbox is mocked in this example).
const RELAY: &str = "relay.example.com";

fn main() -> anyhow::Result<()> {
    let wallet = Wallet::new();
    println!(
        "wallet provisioned two suites: v1 = X25519 (32-byte key), \
         v2 = X-Wing ({}-byte key)\n",
        v2::ENCAPSULATION_KEY_SIZE,
    );

    // === v1: classical, the recommended suite today ===
    let secret = random_bytes::<16>();
    let conn = wallet.connection_string(Version::V1, RELAY, &secret);
    println!("wallet issues v1 connection string:\n  {}", display::abbreviate(&conn));

    // Client parses the string and seals a request *accordingly* (v1 → X25519
    // AuthPSK). v1 binds a client static key, registered out of band.
    let parsed = ParsedConn::parse(&conn)?;
    let client = v1::gen_keypair();
    let wire = client_seal(&parsed, Some((&client.0, &client.1)), b"pay_invoice lnbc1...")?;
    let body = wallet.open(parsed.version, &secret, Some(&client.1), &wire)?;
    display::round_trip(parsed.version, wire.len(), &body);

    // === v2: post-quantum upgrade — same string format, same client path ===
    let secret = random_bytes::<16>();
    let conn = wallet.connection_string(Version::V2, RELAY, &secret);
    println!("wallet issues v2 connection string:\n  {}", display::abbreviate(&conn));

    // v2 (X-Wing) has no authenticated-KEM mode, so there is NO client static
    // key — the connection secret (PSK) is the sole client authenticator.
    let parsed = ParsedConn::parse(&conn)?;
    let wire = client_seal(&parsed, None, b"pay_invoice lnbc1...")?;
    let body = wallet.open(parsed.version, &secret, None, &wire)?;
    display::round_trip(parsed.version, wire.len(), &body);

    // === Rejected: an unknown version is hard-rejected at parse time ===
    let bad = conn.replace("v=2", "v=3");
    match ParsedConn::parse(&bad) {
        Ok(_) => bail!("an unknown version should have been rejected"),
        Err(e) => println!("rejected unknown version: {e}"),
    }

    // === Rejected: a wrong connection secret fails PSK auth (shown on v2) ===
    let mut forged = parsed.clone();
    forged.secret = random_bytes::<16>().to_vec();
    let wire = client_seal(&forged, None, b"pay_invoice lnbc1...")?;
    match wallet.open(Version::V2, &secret, None, &wire) {
        Ok(_) => bail!("a request with the wrong secret should have been rejected"),
        Err(e) => println!("rejected wrong connection secret: {e}"),
    }

    println!("\nok");
    Ok(())
}

/// The versions this client/wallet understand. Unknown → hard reject.
#[derive(Clone, Copy)]
enum Version {
    V1,
    V2,
}

impl Version {
    fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "1" => Ok(Version::V1),
            "2" => Ok(Version::V2),
            other => bail!("UNSUPPORTED_VERSION: {other}"),
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Version::V1 => 1,
            Version::V2 => 2,
        }
    }
}

/// A parsed connection string. `wallet_pk` stays raw bytes until `version` says
/// how to interpret it — 32 bytes for v1, 1216 for v2 — which is exactly why the
/// version must be read before the key.
#[derive(Clone)]
struct ParsedConn {
    #[allow(dead_code)] // relay routing is mocked in this example
    relay: String,
    version: Version,
    wallet_pk: Vec<u8>,
    secret: Vec<u8>,
}

impl ParsedConn {
    fn parse(uri: &str) -> anyhow::Result<Self> {
        let rest = uri.strip_prefix("bwc://").ok_or_else(|| anyhow!("not a bwc:// URI"))?;
        let (relay, query) = rest.split_once('?').ok_or_else(|| anyhow!("missing query"))?;

        let (mut version, mut wallet_pk, mut secret) = (None, None, None);
        for pair in query.split('&') {
            let (key, val) = pair.split_once('=').ok_or_else(|| anyhow!("malformed param"))?;
            match key {
                "v" => version = Some(Version::parse(val)?),
                "wallet_pk" => wallet_pk = Some(hex::decode(val)?),
                "secret" => secret = Some(hex::decode(val)?),
                _ => {} // ignore unknown params (forward-compat)
            }
        }

        Ok(ParsedConn {
            relay: relay.to_string(),
            version: version.ok_or_else(|| anyhow!("missing v"))?,
            wallet_pk: wallet_pk.ok_or_else(|| anyhow!("missing wallet_pk"))?,
            secret: secret.ok_or_else(|| anyhow!("missing secret"))?,
        })
    }
}

/// The wallet: holds a long-lived identity for each suite and opens requests.
struct Wallet {
    v1: (v1::PrivateKey, v1::PublicKey),
    v2: (v2::DecapsulationKey, v2::EncapsulationKey),
}

impl Wallet {
    fn new() -> Self {
        Self { v1: v1::gen_keypair(), v2: v2::gen_keypair() }
    }

    /// Mint a connection string; `wallet_pk=` carries the recipient key for `version`.
    fn connection_string(&self, version: Version, relay: &str, secret: &[u8]) -> String {
        let wallet_pk = match version {
            Version::V1 => hex::encode(&v1::pk_bytes(&self.v1.1)),
            Version::V2 => hex::encode(&v2::ek_bytes(&self.v2.1)),
        };
        format!("bwc://{relay}?v={}&wallet_pk={wallet_pk}&secret={}", version.as_u8(), hex::encode(secret))
    }

    /// Authenticate + decrypt a request under the connection's version.
    fn open(
        &self,
        version: Version,
        secret: &[u8],
        client_pk: Option<&v1::PublicKey>,
        wire: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        match version {
            Version::V1 => {
                let client_pk =
                    client_pk.ok_or_else(|| anyhow!("v1 requires the client's registered key"))?;
                v1::open(&self.v1.0, client_pk, secret, wire)
            }
            Version::V2 => v2::open(&self.v2.0, secret, wire),
        }
    }
}

/// The client: parse `v`, then seal the request with the matching suite.
fn client_seal(
    conn: &ParsedConn,
    client_v1: Option<(&v1::PrivateKey, &v1::PublicKey)>,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match conn.version {
        Version::V1 => {
            let wallet_pk = v1::pk_from_bytes(&conn.wallet_pk)?;
            let client = client_v1
                .ok_or_else(|| anyhow!("v1 requires a client identity keypair (AuthPSK)"))?;
            Ok(v1::seal(&wallet_pk, client, &conn.secret, plaintext))
        }
        Version::V2 => v2::seal(&conn.wallet_pk, &conn.secret, plaintext),
    }
}

/// v1 suite: X25519 HPKE in AuthPSK mode. Wire layout: `enc(32) || ciphertext`.
mod v1 {
    use anyhow::{anyhow, bail};
    use hpke::{
        Deserializable, Kem as KemTrait, OpModeR, OpModeS, PskBundle, Serializable,
        aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver,
        setup_sender,
    };
    use hpke_demo::rng::OsRng;

    type Kem = X25519HkdfSha256;
    type Kdf = HkdfSha256;
    type Aead = ChaCha20Poly1305;

    pub type PublicKey = <Kem as KemTrait>::PublicKey;
    pub type PrivateKey = <Kem as KemTrait>::PrivateKey;
    type EncappedKey = <Kem as KemTrait>::EncappedKey;

    /// Length of a serialized X25519 KEM public key (and encapsulated key).
    const PUBLIC_KEY_LEN: usize = 32;
    /// HPKE `info`, binding the sealed message to this version + direction.
    const INFO: &[u8] = b"bwc-v1 request";
    /// PSK identifier paired with the connection secret (HPKE wants a non-empty pair).
    const PSK_ID: &[u8] = b"bwc-connection";

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

    /// AuthPSK-seal to `wallet_pk`, authenticating as `client` under `secret`.
    pub fn seal(
        wallet_pk: &PublicKey,
        client: (&PrivateKey, &PublicKey),
        secret: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let psk = PskBundle::new(secret, PSK_ID).expect("non-empty psk + psk_id");
        let mode = OpModeS::AuthPsk((client.0.clone(), client.1.clone()), psk);
        let (enc, mut ctx) = setup_sender::<Aead, Kdf, Kem, _>(&mode, wallet_pk, INFO, &mut OsRng)
            .expect("sender setup");
        let ciphertext = ctx.seal(plaintext, b"").expect("seal");
        [enc.to_bytes().as_slice(), &ciphertext].concat()
    }

    /// Open a wire message (`enc || ciphertext`) from the registered `client_pk`.
    pub fn open(
        wallet_sk: &PrivateKey,
        client_pk: &PublicKey,
        secret: &[u8],
        wire: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if wire.len() < PUBLIC_KEY_LEN {
            bail!("v1 message too short");
        }
        let (enc_bytes, ciphertext) = wire.split_at(PUBLIC_KEY_LEN);
        let enc = EncappedKey::from_bytes(enc_bytes).map_err(|e| anyhow!("malformed enc: {e:?}"))?;

        let psk = PskBundle::new(secret, PSK_ID).map_err(|e| anyhow!("psk bundle: {e:?}"))?;
        let mode = OpModeR::AuthPsk(client_pk.clone(), psk);
        let mut ctx = setup_receiver::<Aead, Kdf, Kem>(&mode, wallet_sk, &enc, INFO)
            .map_err(|e| anyhow!("receiver setup: {e:?}"))?;
        ctx.open(ciphertext, b"").map_err(|_| anyhow!("v1 authentication/decryption failed"))
    }
}

/// v2 suite: X-Wing (X25519 + ML-KEM-768) KEM + HKDF-SHA256 + ChaCha20Poly1305.
/// Post-quantum. X-Wing isn't an HPKE KEM, so the KEM→KDF→AEAD schedule is built
/// by hand; PSK mode (the connection secret authenticates the client). Wire
/// layout: `xwing_ciphertext(1120) || aead_ciphertext`.
mod v2 {
    use anyhow::{anyhow, bail};
    use chacha20poly1305::{
        ChaCha20Poly1305, Key as AeadKey, Nonce,
        aead::{Aead, KeyInit},
    };
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x_wing::{
        Ciphertext, Decapsulate, Encapsulate, Kem as KemTrait, KeyExport, TryKeyInit, XWingKem,
    };

    pub use x_wing::{DecapsulationKey, EncapsulationKey, ENCAPSULATION_KEY_SIZE};

    /// HKDF `info`, binding the derived key to this version + direction.
    const INFO: &[u8] = b"bwc-v2 request";

    pub fn gen_keypair() -> (DecapsulationKey, EncapsulationKey) {
        XWingKem::generate_keypair()
    }

    pub fn ek_bytes(ek: &EncapsulationKey) -> Vec<u8> {
        ek.to_bytes().as_slice().to_vec()
    }

    /// PSK-seal to the wallet's X-Wing key: encapsulate, derive, then AEAD.
    pub fn seal(wallet_ek_bytes: &[u8], secret: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key = x_wing::Key::<EncapsulationKey>::try_from(wallet_ek_bytes)
            .map_err(|_| anyhow!("bad X-Wing key length"))?;
        let ek = EncapsulationKey::new(&key).map_err(|_| anyhow!("invalid X-Wing key"))?;

        let (ct, shared) = ek.encapsulate();
        let (aead_key, nonce) = derive(shared.as_slice(), secret);
        let sealed = ChaCha20Poly1305::new(AeadKey::from_slice(&aead_key))
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| anyhow!("v2 seal failed"))?;

        Ok([ct.as_slice(), &sealed].concat())
    }

    pub fn open(dk: &DecapsulationKey, secret: &[u8], wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        if wire.len() < x_wing::CIPHERTEXT_SIZE {
            bail!("v2 message too short");
        }
        let (ct_bytes, sealed) = wire.split_at(x_wing::CIPHERTEXT_SIZE);
        let ct = Ciphertext::try_from(ct_bytes).map_err(|_| anyhow!("bad X-Wing ciphertext"))?;

        let shared = dk.decapsulate(&ct);
        let (aead_key, nonce) = derive(shared.as_slice(), secret);
        ChaCha20Poly1305::new(AeadKey::from_slice(&aead_key))
            .decrypt(Nonce::from_slice(&nonce), sealed)
            .map_err(|_| anyhow!("v2 authentication/decryption failed"))
    }

    /// Derive the AEAD key + nonce from the KEM shared secret, mixing the
    /// connection secret in as the HKDF salt (PSK) so only a holder of the secret
    /// can produce or open a message. A fresh shared secret per message keeps the
    /// nonce unique.
    fn derive(shared: &[u8], secret: &[u8]) -> ([u8; 32], [u8; 12]) {
        let hkdf = Hkdf::<Sha256>::new(Some(secret), shared);
        let mut okm = [0u8; 44];
        hkdf.expand(INFO, &mut okm).expect("HKDF expand of 44 bytes never fails");
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        key.copy_from_slice(&okm[..32]);
        nonce.copy_from_slice(&okm[32..]);
        (key, nonce)
    }
}

/// Minimal hex codec (this example is self-contained; swap for any other).
mod hex {
    use anyhow::{anyhow, bail};

    const HEX: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }

    pub fn decode(s: &str) -> anyhow::Result<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            bail!("odd-length hex");
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}")))
            .collect()
    }
}

/// Console output for the demo.
mod display {
    use super::Version;

    pub fn round_trip(version: Version, wire_len: usize, body: &[u8]) {
        println!(
            "  client sealed {wire_len} B (v{}); wallet opened -> {:?}\n",
            version.as_u8(),
            String::from_utf8_lossy(body),
        );
    }

    /// Shorten a connection string's (possibly ~2.4 KB) `wallet_pk=` value for display.
    pub fn abbreviate(conn: &str) -> String {
        let Some(start) = conn.find("wallet_pk=").map(|i| i + "wallet_pk=".len()) else {
            return conn.to_string();
        };
        let end = conn[start..].find('&').map_or(conn.len(), |o| start + o);
        let val = &conn[start..end];
        if val.len() <= 24 {
            return conn.to_string();
        }
        format!("{}{}…({} hex chars){}", &conn[..start], &val[..16], val.len(), &conn[end..])
    }
}
