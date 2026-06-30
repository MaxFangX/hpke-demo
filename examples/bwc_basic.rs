//! **BWC basic — the minimal client ⇄ wallet round trip.**
//!
//! The recommended starting point. A wallet mints a [BWC connection string]; the
//! client parses it and seals a request to the wallet; the wallet authenticates
//! the client and seals a reply. Each direction is a one-shot HPKE context in
//! AuthPSK mode: the connection `secret` is the PSK, and each sender's X25519
//! key is bound into the KEM.
//!
//! In-memory — no relay. See `bwc_full` for the replay-protected, served version.
//!
//! Run with:
//! ```text
//! $ cargo run --example bwc_basic
//! ```
//!
//! [BWC connection string]: hpke_demo::connect

use anyhow::bail;
use hpke_demo::channel;
use hpke_demo::connect::{ConnString, INFO_REQUEST, INFO_RESPONSE, Version};
use hpke_demo::rng::random_bytes;

fn main() -> anyhow::Result<()> {
    // --- Wallet: provision an identity, mint a connection string --- //
    let (wallet_sk, wallet_pk) = channel::gen_keypair();
    let secret = random_bytes::<16>().to_vec();
    let conn = ConnString {
        relay: "relay.example.com".to_string(),
        version: Version::V1,
        wallet_pk: channel::kem_pk_bytes(&wallet_pk).to_vec(),
        secret: secret.clone(),
        // No relay auth in the minimal round trip; see bwc_full.
        token: None,
        relay_params: Vec::new(),
    };
    println!("wallet issues connection string:\n  {}\n", conn.to_uri());

    // --- Client: parse it, then seal a request to the wallet --- //
    let parsed = ConnString::parse(&conn.to_uri())?;
    if parsed.version != Version::V1 {
        bail!("this example implements v1 only; see bwc_post_quantum_upgrade for v2");
    }
    let wallet_pk = channel::kem_pk_from_bytes(&parsed.wallet_pk)?;
    let (client_sk, client_pk) = channel::gen_keypair();
    // The client registers `client_pk` with the wallet during bootstrap (modeled
    // here by handing it over directly). TODO: a real registration handshake.
    let request = channel::seal(
        (&client_sk, &client_pk),
        &wallet_pk,
        &parsed.secret,
        INFO_REQUEST,
        b"pay_invoice lnbc1...",
    );
    println!("client -> wallet: sealed {}-byte request", request.len());

    // --- Wallet: authenticate + decrypt, then seal a reply --- //
    let body = channel::open(&wallet_sk, &client_pk, &secret, INFO_REQUEST, &request)?;
    println!("wallet: client authenticated, request = {:?}", String::from_utf8_lossy(&body));

    let reply = channel::seal(
        (&wallet_sk, &wallet_pk),
        &client_pk,
        &secret,
        INFO_RESPONSE,
        b"preimage 0123...",
    );
    let body = channel::open(&client_sk, &wallet_pk, &parsed.secret, INFO_RESPONSE, &reply)?;
    println!("client: wallet authenticated, response = {:?}", String::from_utf8_lossy(&body));

    // --- Rejected: a client that doesn't hold the connection secret --- //
    let wrong_secret = random_bytes::<16>().to_vec();
    let forged = channel::seal(
        (&client_sk, &client_pk),
        &wallet_pk,
        &wrong_secret,
        INFO_REQUEST,
        b"pay_invoice lnbc1...",
    );
    match channel::open(&wallet_sk, &client_pk, &secret, INFO_REQUEST, &forged) {
        Ok(_) => bail!("a request with the wrong secret should have been rejected"),
        Err(e) => println!("wallet: rejected wrong connection secret ({e})"),
    }

    println!("\nok");
    Ok(())
}
