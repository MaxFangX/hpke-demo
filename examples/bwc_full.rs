//! **BWC full — the served deployment: an axum relay proxying to a wallet server.**
//!
//! Builds on `bwc_basic`'s X25519 AuthPSK sealing and the BWC connection string,
//! and wires it through an actual (in-process) untrusted relay:
//!
//! - a **wallet** server (axum) exposing `POST /request`: authenticate +
//!   decrypt the sealed request, run it, seal a reply;
//! - an untrusted **relay** (axum) that authenticates the client with a bearer
//!   token it issued, then forwards each request to the wallet inline and returns
//!   the sealed reply — it holds no keys, reads no plaintext, and only ever moves
//!   opaque bytes; and
//! - a **client** (reqwest) that seals a request, posts it to the relay, and gets
//!   the sealed reply back on the same call.
//!
//! Each role is its own module ([`wallet`], [`relay`], [`client`]) with private
//! fields and a small public API, so the deliberate surface of each is explicit;
//! they share only the wire framing at the bottom of the file.
//!
//! The relay is a synchronous proxy: like the Lexe gateway forwarding to the
//! backend, its handler makes an outbound call to the wallet and returns the
//! wallet's response to the original caller. (A real relay might instead hold a
//! wallet-initiated connection, to reach a wallet behind NAT.)
//!
//! The relay also gates who may post to a connection: it issues an opaque bearer
//! token bound to that connection, the wallet embeds it in the connection string,
//! and the client resends it as an `Authorization: Bearer` header. This
//! client↔relay check is separate from the end-to-end client↔wallet auth, and its
//! scheme — here just a random capability string checked against an in-memory
//! table — is the vendor's choice, not part of BWC.
//!
//! The wallet still defends against replay: the client tags every request with a
//! fresh nonce + send time inside the sealed payload, and the wallet — trusting
//! only its own clock — rejects stale requests and nonces it has already seen.
//!
//! Everything here that isn't HPKE (axum, reqwest, the bearer token, the JSON
//! envelope, the task plumbing) is ordinary and swappable; only
//! `channel::{seal,open}` is BWC-specific.
//!
//! TODO:
//! - A real, standalone relay service: rate limiting, token issuance/revocation,
//!   and routing to the wallet by a per-connection token rather than its pubkey.
//! - Replay protection on the response direction, with client-side dedup.
//! - A client-key registration handshake (bootstrap).
//!
//! Run with:
//! ```text
//! $ cargo run --example bwc_full
//! ```

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::bail;
use hpke_demo::channel;
use hpke_demo::connect::{ConnString, Version};
use hpke_demo::rng::random_bytes;
use lexe_hex::hex;
use lexe_serde::hexstr_or_bytes;
use lexe_tokio::{notify_once::NotifyOnce, task::LxTask};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use client::Client;
use relay::Relay;
use wallet::Wallet;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --- Bootstrap: wallet identity, connection secret, client identity --- //
    let (wallet_sk, wallet_pk) = channel::gen_keypair();
    let (client_sk, client_pk) = channel::gen_keypair();
    let secret = random_bytes::<16>().to_vec();
    let conn_id = hex::encode(&channel::kem_pk_bytes(&wallet_pk));

    // The relay issues a bearer token gating who may post to this connection, and
    // remembers which connection it grants access to. A real relay hands this to
    // the wallet when it comes online (e.g. after the user authenticates with the
    // wallet vendor); the wallet then embeds it in the connection string. The
    // scheme is the vendor's choice, not part of BWC — here, an opaque random
    // capability string, valid only for posting to `conn_id`.
    let token = hex::encode(&random_bytes::<32>());

    let shutdown = NotifyOnce::new();

    // --- Wallet: serve `POST /request` in the background --- //
    let wallet_listener = TcpListener::bind("127.0.0.1:0").await?;
    let wallet_addr = wallet_listener.local_addr()?;
    let wallet_task = {
        // `client_pk` is registered out of band during bootstrap (modeled here by
        // handing it to the wallet directly).
        let wallet = Wallet::new(
            wallet_sk,
            wallet_pk.clone(),
            secret.clone(),
            client_pk.clone(),
        );
        let app = wallet.router();
        let shutdown = shutdown.clone();
        LxTask::spawn("wallet", async move {
            axum::serve(wallet_listener, app)
                .with_graceful_shutdown(shutdown.recv_owned())
                .await
                .expect("wallet serve failed");
        })
    };

    // --- Relay: forward each client request to the wallet, keyed by conn --- //
    let relay_listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_addr = relay_listener.local_addr()?;
    let relay_task = {
        // The wallet registers its address with the relay out of band.
        let wallets = HashMap::from([(conn_id.clone(), format!("http://{wallet_addr}"))]);
        let tokens = HashMap::from([(token.clone(), conn_id)]);
        let app = Relay::new(wallets, tokens).router();
        let shutdown = shutdown.clone();
        LxTask::spawn("relay", async move {
            axum::serve(relay_listener, app)
                .with_graceful_shutdown(shutdown.recv_owned())
                .await
                .expect("relay serve failed");
        })
    };

    // --- Wallet mints the connection string (pointing at the relay) --- //
    let conn_string = ConnString {
        relay: relay_addr.to_string(),
        version: Version::V1,
        wallet_pk: channel::kem_pk_bytes(&wallet_pk).to_vec(),
        secret: secret.clone(),
        token: Some(token),
        // A param BWC doesn't define, carried through to the relay (say, a
        // routing hint the relay operator understands). The client forwards it
        // verbatim without knowing what it means.
        relay_params: vec![("region".to_string(), "us-west".to_string())],
    };
    println!(
        "wallet issues connection string:\n  {}\n",
        conn_string.to_uri()
    );

    // --- Client: parse the string, then exercise the wallet through the relay --- //
    let conn = ConnString::parse(&conn_string.to_uri())?;
    if conn.version != Version::V1 {
        bail!("this example implements v1 only; see bwc_post_quantum_upgrade for v2");
    }
    let client = Client::new(conn, client_sk, client_pk)?;

    // A fresh, authorized request is accepted and answered with a sealed reply.
    let fresh = client.seal(now_secs(), b"pay_invoice lnbc1...");
    client.round_trip("authorized request", &fresh).await?;

    // Replaying the very same sealed bytes (e.g. by a malicious relay) is rejected.
    client.round_trip("replayed request", &fresh).await?;

    // A request timestamped outside the freshness window is rejected.
    let stale = client.seal(now_secs() - 10 * 60, b"transfer 2 BTC");
    client.round_trip("stale request", &stale).await?;

    // A client without the relay's token never reaches the wallet: the relay 401s.
    let barred = client.seal(now_secs(), b"pay_invoice lnbc1...");
    client
        .round_trip_unauthed("unauthorized request", &barred)
        .await?;

    // --- Shut down the servers, propagating any panic --- //
    shutdown.send();
    wallet_task.await.expect("wallet task panicked");
    relay_task.await.expect("relay task panicked");

    println!("\nok");
    Ok(())
}

/// The wallet server: authenticates clients (AuthPSK), rejects stale or replayed
/// requests off its own clock, and seals replies.
mod wallet {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use anyhow::bail;
    use axum::{extract::State, routing::post, Json, Router};
    use hpke_demo::channel::{self, PrivateKey, PublicKey};
    use hpke_demo::connect::{INFO_REQUEST, INFO_RESPONSE};

    use super::{now_secs, response, Sealed, NONCE_LEN, TS_LEN};

    /// Reject requests whose timestamp is more than this from the wallet's clock.
    const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;

    /// Cloned per request by axum's `State` extractor; the replay cache is shared
    /// behind `Arc<Mutex>`. All fields are private — build via [`Wallet::new`].
    #[derive(Clone)]
    pub struct Wallet {
        sk: PrivateKey,
        pk: PublicKey,
        secret: Vec<u8>,
        client_pk: PublicKey,
        /// Nonces seen this session -> the wallet's receive time (unix secs).
        seen: Arc<Mutex<HashMap<[u8; NONCE_LEN], u64>>>,
    }

    impl Wallet {
        /// Provision a wallet with its keypair, the connection `secret` (PSK), and
        /// the `client_pk` registered out of band. The replay cache starts empty.
        pub fn new(sk: PrivateKey, pk: PublicKey, secret: Vec<u8>, client_pk: PublicKey) -> Self {
            Self {
                sk,
                pk,
                secret,
                client_pk,
                seen: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        /// The axum app: `POST /request`.
        pub fn router(self) -> Router {
            Router::new()
                .route("/request", post(Self::post_request))
                .with_state(self)
        }

        /// Authenticate + decrypt a request, run it, and seal a reply. (A
        /// production wallet might drop replays silently; we answer so the demo
        /// shows the outcome.)
        async fn post_request(
            State(wallet): State<Wallet>,
            Json(req): Json<Sealed>,
        ) -> Json<Sealed> {
            let payload = match wallet.handle(&req.sealed) {
                Ok(body) => {
                    println!(
                        "wallet: accepted request {:?}",
                        String::from_utf8_lossy(&body)
                    );
                    response::ok(format!("ack: {}", String::from_utf8_lossy(&body)).as_bytes())
                }
                Err(e) => {
                    println!("wallet: rejected request ({e})");
                    response::err(&e.to_string())
                }
            };
            let sealed = channel::seal(
                (&wallet.sk, &wallet.pk),
                &wallet.client_pk,
                &wallet.secret,
                INFO_RESPONSE,
                &payload,
            );
            Json(Sealed { sealed })
        }

        /// Authenticate + decrypt a request, then enforce freshness and no-replay,
        /// returning the request body. Errors are surfaced to the client as
        /// reasons.
        fn handle(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
            let now = now_secs();
            let mut seen = self.seen.lock().unwrap();

            // Expire nonces once no replay of them could still pass the freshness
            // check (a captured request is acceptable across a 2x-skew window).
            seen.retain(|_, seen_at| now.saturating_sub(*seen_at) <= 2 * MAX_CLOCK_SKEW_SECS);

            // Authenticate + decrypt: AuthPSK open only succeeds for a sender
            // holding both the connection secret (PSK) and the registered key.
            let payload =
                channel::open(&self.sk, &self.client_pk, &self.secret, INFO_REQUEST, wire)?;

            // Parse `nonce || timestamp || body` (authenticated by the seal).
            if payload.len() < NONCE_LEN + TS_LEN {
                bail!("malformed request");
            }
            let (nonce, rest) = payload.split_at(NONCE_LEN);
            let (ts_bytes, body) = rest.split_at(TS_LEN);
            let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("len checked");
            let timestamp = u64::from_be_bytes(ts_bytes.try_into().expect("len checked"));

            // Reject stale/future requests, then replays.
            if now.abs_diff(timestamp) > MAX_CLOCK_SKEW_SECS {
                bail!("clock skew: timestamp outside the freshness window");
            }
            if seen.contains_key(&nonce) {
                bail!("replayed: nonce already seen this session");
            }
            seen.insert(nonce, now);

            Ok(body.to_vec())
        }
    }
}

/// The untrusted relay: a synchronous proxy that authenticates the client with a
/// bearer token, then forwards opaque sealed bytes to the wallet. It holds no
/// keys and never reads plaintext.
mod relay {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use anyhow::{anyhow, bail};
    use axum::{
        extract::{Path, Query, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
        Json, Router,
    };

    use super::Sealed;

    /// Cloned per request by axum's `State` extractor; the routing table and
    /// issued tokens are shared behind `Arc`. All fields are private — build via
    /// [`Relay::new`].
    #[derive(Clone)]
    pub struct Relay {
        http: reqwest::Client,
        /// Maps a connection id (hex of the wallet pubkey) to how the relay
        /// reaches that wallet — here, a base URL to forward to. In-memory for the
        /// demo; a real relay would persist this (a DB) and, depending on
        /// deployment, might do more than forward: e.g. push-wake a mobile wallet
        /// when a sealed request arrives for it, rather than assume it is already
        /// listening.
        wallets: Arc<HashMap<String, String>>,
        /// Bearer tokens the relay has issued -> the connection each one grants
        /// access to. A token is a pure capability: holding it lets you post to
        /// its one connection and nothing else.
        tokens: Arc<HashMap<String, String>>,
    }

    impl Relay {
        /// Build a relay over its routing table (`wallets`: connection id -> wallet
        /// base URL) and the bearer tokens it has issued (`tokens`: token ->
        /// connection id).
        pub fn new(wallets: HashMap<String, String>, tokens: HashMap<String, String>) -> Self {
            let http = reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build reqwest client");
            Self {
                http,
                wallets: Arc::new(wallets),
                tokens: Arc::new(tokens),
            }
        }

        /// The axum app: `POST /{conn}/request`.
        pub fn router(self) -> Router {
            Router::new()
                .route("/{conn}/request", post(Self::forward_request))
                .with_state(self)
        }

        /// Authenticate the client, then forward the sealed request to the wallet
        /// for `conn`, returning its sealed reply inline (like the Lexe gateway
        /// calling the backend in-handler). Params the client forwarded (`Query`)
        /// are the connection-string params BWC didn't define; a real relay might
        /// route off them, here we just log them.
        async fn forward_request(
            State(relay): State<Relay>,
            Path(conn): Path<String>,
            Query(relay_params): Query<Vec<(String, String)>>,
            headers: HeaderMap,
            Json(req): Json<Sealed>,
        ) -> Response {
            if let Err(e) = relay.authorize(&conn, &headers) {
                eprintln!("relay: rejected unauthorized client ({e})");
                return (StatusCode::UNAUTHORIZED, format!("unauthorized: {e}")).into_response();
            }
            let Some(wallet_url) = relay.wallets.get(&conn) else {
                return (StatusCode::NOT_FOUND, "unknown connection").into_response();
            };
            if !relay_params.is_empty() {
                println!("relay: forwarding to {conn} (relay params: {relay_params:?})");
            }
            // Synchronous proxy: forward inline to the wallet and hand its sealed
            // reply straight back (cf. the Lexe gateway calling the backend
            // in-handler). The relay only moves opaque bytes; a transport failure
            // becomes a 502. The inline `async` block lets the reqwest chain use
            // `?` even though the handler itself returns a `Response`.
            let forwarded = async {
                relay
                    .http
                    .post(format!("{wallet_url}/request"))
                    .json(&req)
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<Sealed>()
                    .await
            }
            .await;
            match forwarded {
                Ok(reply) => Json(reply).into_response(),
                Err(e) => {
                    eprintln!("relay: wallet unreachable ({e})");
                    StatusCode::BAD_GATEWAY.into_response()
                }
            }
        }

        /// Admit the client only if it presents a `Bearer` token the relay issued
        /// for exactly this connection. This gates access to the transport; it is
        /// not the end-to-end client↔wallet authentication (the HPKE layer's job).
        fn authorize(&self, conn: &str, headers: &HeaderMap) -> anyhow::Result<()> {
            let token = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .ok_or_else(|| anyhow!("missing bearer token"))?;
            match self.tokens.get(token) {
                Some(granted) if granted == conn => Ok(()),
                Some(_) => bail!("token not valid for this connection"),
                None => bail!("unknown token"),
            }
        }
    }
}

/// The client: seals requests, posts them through the relay with its bearer
/// token, and opens the wallet's sealed replies.
mod client {
    use std::time::Duration;

    use hpke_demo::channel::{self, PrivateKey, PublicKey};
    use hpke_demo::connect::{ConnString, INFO_REQUEST, INFO_RESPONSE};
    use hpke_demo::rng::random_bytes;
    use lexe_hex::hex;

    use super::{response, Sealed, NONCE_LEN};

    /// Built from a parsed connection string via [`Client::new`]; all fields are
    /// private.
    pub struct Client {
        http: reqwest::Client,
        base: String,
        conn: String,
        sk: PrivateKey,
        pk: PublicKey,
        wallet_pk: PublicKey,
        secret: Vec<u8>,
        /// Optional bearer token gating access to the relay,
        /// sent as `Authorization: Bearer`.
        token: Option<String>,
        /// Connection-string params the client didn't recognize; forwarded
        /// verbatim to the relay on each request.
        relay_params: Vec<(String, String)>,
    }

    impl Client {
        /// Build a client from a parsed connection string and the client's keypair
        /// (registered with the wallet out of band). The `token` moves out of the
        /// URL into a Bearer header; unrecognized params ride along to the relay.
        pub fn new(conn: ConnString, sk: PrivateKey, pk: PublicKey) -> anyhow::Result<Self> {
            let http = reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?;
            Ok(Self {
                http,
                base: format!("http://{}", conn.relay),
                conn: hex::encode(&conn.wallet_pk),
                wallet_pk: channel::kem_pk_from_bytes(&conn.wallet_pk)?,
                sk,
                pk,
                secret: conn.secret,
                token: conn.token,
                relay_params: conn.relay_params,
            })
        }

        /// Seal `nonce || timestamp || body` to the wallet (fresh nonce each call).
        pub fn seal(&self, timestamp: u64, body: &[u8]) -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&random_bytes::<NONCE_LEN>());
            payload.extend_from_slice(&timestamp.to_be_bytes());
            payload.extend_from_slice(body);
            channel::seal(
                (&self.sk, &self.pk),
                &self.wallet_pk,
                &self.secret,
                INFO_REQUEST,
                &payload,
            )
        }

        /// Post a sealed request through the relay with the connection's bearer
        /// token, open the sealed reply, and print the outcome.
        pub async fn round_trip(&self, label: &str, sealed: &[u8]) -> anyhow::Result<()> {
            self.send(label, sealed, self.token.as_deref()).await
        }

        /// As [`round_trip`](Self::round_trip), but presenting no token — to show
        /// the relay bar the request before it ever reaches the wallet.
        pub async fn round_trip_unauthed(&self, label: &str, sealed: &[u8]) -> anyhow::Result<()> {
            self.send(label, sealed, None).await
        }

        /// Post a sealed request, open the sealed reply, print the outcome. A relay
        /// rejection (e.g. an unauthorized client) surfaces as a non-2xx status
        /// and never reaches the wallet.
        async fn send(
            &self,
            label: &str,
            sealed: &[u8],
            token: Option<&str>,
        ) -> anyhow::Result<()> {
            let mut req = self
                .http
                .post(format!("{}/{}/request", self.base, self.conn))
                .query(&self.relay_params)
                .json(&Sealed {
                    sealed: sealed.to_vec(),
                });
            if let Some(token) = token {
                req = req.bearer_auth(token);
            }

            let resp = req.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                println!("{label}: relay rejected -> {status} ({body})");
                return Ok(());
            }

            let reply = resp.json::<Sealed>().await?;
            let payload = channel::open(
                &self.sk,
                &self.wallet_pk,
                &self.secret,
                INFO_RESPONSE,
                &reply.sealed,
            )?;
            match response::decode(&payload) {
                Ok(body) => println!("{label}: accepted -> {:?}", String::from_utf8_lossy(&body)),
                Err(reason) => println!("{label}: rejected -> {reason}"),
            }
            Ok(())
        }
    }
}

// --- Shared wire framing & helpers (used by all three roles) --- //

/// Length of the per-request nonce in the sealed plaintext framing
/// (`nonce || timestamp || body`).
const NONCE_LEN: usize = 16;
/// Length of the big-endian unix-seconds timestamp in the framing.
const TS_LEN: usize = 8;

/// A sealed message envelope — `enc || ciphertext`, opaque to the relay. Carried
/// in both directions (client → wallet request, wallet → client reply).
#[derive(Serialize, Deserialize)]
struct Sealed {
    #[serde(with = "hexstr_or_bytes")]
    sealed: Vec<u8>,
}

/// Current unix time in seconds. Both parties read their own clock (here, one).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

/// Framing of the sealed response payload: a status byte, then the body.
mod response {
    const OK: u8 = 0;
    const ERR: u8 = 1;

    /// Frame a successful reply.
    pub fn ok(body: &[u8]) -> Vec<u8> {
        [&[OK], body].concat()
    }

    /// Frame a rejection reason.
    pub fn err(reason: &str) -> Vec<u8> {
        [&[ERR], reason.as_bytes()].concat()
    }

    /// Split a decrypted response into `Ok(reply)` or `Err(reason)`.
    pub fn decode(payload: &[u8]) -> Result<Vec<u8>, String> {
        match payload.split_first() {
            Some((&OK, body)) => Ok(body.to_vec()),
            Some((&ERR, reason)) => Err(String::from_utf8_lossy(reason).into_owned()),
            _ => Err("malformed response".to_string()),
        }
    }
}
