//! The BWC connection string.
//!
//! A wallet hands the client `bwc://<relay>?v=<version>&wallet_pk=<hex>&secret=<hex>`
//! out of band (QR, deeplink, paste); the client parses it and seals requests to
//! `wallet_pk` accordingly. Hex uses the zero-dep [`lexe_hex`] crate — a minor
//! utility any implementation could swap for its own.

use anyhow::{anyhow, bail};
use lexe_hex::hex;

/// A BWC connection string — built by the wallet, parsed by the client.
///
/// `wallet_pk` stays raw bytes until `version` says how to interpret it (32 bytes
/// for v1's X25519 key), which is why the version is read before the key.
#[derive(Clone)]
pub struct ConnString {
    pub relay: String,
    pub version: Version,
    pub wallet_pk: Vec<u8>,
    pub secret: Vec<u8>,
    /// Optional bearer credential authenticating the *client* to the relay —
    /// orthogonal to the end-to-end client↔wallet auth the HPKE layer provides.
    /// Opaque to BWC; the wallet vendor picks the scheme. Carried in the string
    /// as `token=…`, but [`parse`](Self::parse) lifts it out so the client sends
    /// it as an `Authorization: Bearer` header, keeping it out of URL logs.
    pub token: Option<String>,
    /// Params the client didn't recognize. Forwarded verbatim to the relay on
    /// each request, which may key routing or policy off them.
    pub relay_params: Vec<(String, String)>,
}

impl ConnString {
    /// Render to the `bwc://…` URI the wallet hands out.
    pub fn to_uri(&self) -> String {
        let mut uri = format!(
            "bwc://{}?v={}&wallet_pk={}&secret={}",
            self.relay,
            self.version.as_u8(),
            hex::encode(&self.wallet_pk),
            hex::encode(&self.secret),
        );
        if let Some(token) = &self.token {
            uri.push_str(&format!("&token={token}"));
        }
        for (key, val) in &self.relay_params {
            uri.push_str(&format!("&{key}={val}"));
        }
        uri
    }

    /// Parse a `bwc://…` URI. The version is read first; unknown → hard reject.
    pub fn parse(uri: &str) -> anyhow::Result<Self> {
        let rest = uri.strip_prefix("bwc://").ok_or_else(|| anyhow!("not a bwc:// URI"))?;
        let (relay, query) = rest.split_once('?').ok_or_else(|| anyhow!("missing query"))?;

        let (mut version, mut wallet_pk, mut secret, mut token) = (None, None, None, None);
        let mut relay_params = Vec::new();
        for pair in query.split('&') {
            let (key, val) = pair.split_once('=').ok_or_else(|| anyhow!("malformed param"))?;
            let decode = |v: &str| hex::decode(v).map_err(|e| anyhow!("bad hex: {e:?}"));
            match key {
                "v" => version = Some(Version::parse(val)?),
                "wallet_pk" => wallet_pk = Some(decode(val)?),
                "secret" => secret = Some(decode(val)?),
                // Stripped from the URL; the client resends it as a Bearer header.
                "token" => token = Some(val.to_string()),
                // Unrecognized: forward to the relay untouched.
                _ => relay_params.push((key.to_string(), val.to_string())),
            }
        }

        Ok(ConnString {
            relay: relay.to_string(),
            version: version.ok_or_else(|| anyhow!("missing v"))?,
            wallet_pk: wallet_pk.ok_or_else(|| anyhow!("missing wallet_pk"))?,
            secret: secret.ok_or_else(|| anyhow!("missing secret"))?,
            token,
            relay_params,
        })
    }
}

/// BWC protocol version, carried in the connection string's `v` param.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    /// X25519 HPKE, AuthPSK mode.
    V1,
    /// X-Wing post-quantum KEM, PSK mode (see `bwc_post_quantum_upgrade`).
    V2,
}

impl Version {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "1" => Ok(Version::V1),
            "2" => Ok(Version::V2),
            other => bail!("UNSUPPORTED_VERSION: {other}"),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Version::V1 => 1,
            Version::V2 => 2,
        }
    }
}

/// HPKE `info` strings, binding a sealed message to a protocol version + direction.
pub const INFO_REQUEST: &[u8] = b"bwc-v1 request";
pub const INFO_RESPONSE: &[u8] = b"bwc-v1 response";
