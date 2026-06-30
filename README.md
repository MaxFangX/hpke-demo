# hpke-demo

Runnable examples of one-shot, mutually authenticated RPC over [HPKE] (RFC
9180) through an untrusted relay.

Each request is its own fresh HPKE context (no shared/persisted state). The
`bwc_*` reference examples share their plumbing in [`src/`](src/) (connection
string + sealing layer); the alternatives inline theirs to stay self-contained.
The wallet's public key reaches the client via trusted setup (the connection
string).

## Recommended

Start here. `bwc_basic` is the minimal client ⇄ wallet round trip over a BWC
connection string; `bwc_full` runs the same sealing through a real axum relay —
a synchronous proxy that authenticates the client with a bearer token before
forwarding to a wallet server — with reqwest client/wallet, and adds replay
protection. Both use X25519 HPKE in AuthPSK mode: the connection secret
authenticates the client, and the client's X25519 key is bound into the KEM.

```bash
# Minimal round trip:
$ cargo run --example bwc_basic

# + a served axum relay, reqwest client/wallet, and replay protection:
$ cargo run --example bwc_full
```

## Alternatives

Reach for these only when a constraint rules out the baseline. The constraint is
almost always *what your identity key has to be*:

- **Identity can be a fresh X25519 key** → use the baseline above.
- **Identity must be an existing signing key** — an ed25519 or secp256k1 /
  Bitcoin / Nostr key you already control → a signing variant. A signing key
  isn't a Diffie–Hellman key, so it can't be an HPKE KEM key; instead HPKE base
  mode provides confidentiality and a per-request signature provides
  authentication (the [NIP-47]-style design).

  ```bash
  $ cargo run --example ed25519_signing
  $ cargo run --example secp256k1_signing
  ```

- **Identity must be a secp256k1 KEM key specifically** → `secp256k1_authmode`.
  **Not recommended:** secp256k1 is not a standard HPKE KEM, so this pulls in a
  fork of rust-hpke (see [`Cargo.toml`](Cargo.toml)). If you have a secp256k1
  identity, prefer `secp256k1_signing` over dragging in a non-standard KEM.

  ```bash
  $ cargo run --example secp256k1_authmode
  ```

The alternatives live in [`examples/alt/`](examples/alt/).

## Versioning & post-quantum upgrade

A separate example shows how to make the crypto *upgradeable*. The wallet hands
the client an NWC-style connection string carrying a version:

```
bwc://<relay>?v=1&wallet_pk=<hex pubkey>&secret=<hex>
```

The client parses `v` and seals its request accordingly, so the suite can be
swapped — most importantly classical → post-quantum — by issuing a new string,
with no change to the format or the client's code path:

- **v1** — X25519 HPKE, AuthPSK mode.
- **v2** — [X-Wing] (X25519 + ML-KEM-768) post-quantum KEM, PSK mode. X-Wing has
  no authenticated-KEM variant, so authentication rides the connection `secret`
  (PSK), not the KEM — which is exactly why it survives the swap.

```bash
$ cargo run --example bwc_post_quantum_upgrade
```

Unknown versions are hard-rejected. Since X-Wing isn't an HPKE KEM (RFC 9180
defines none), v2's `encapsulate → HKDF → AEAD` schedule is built by hand rather
than via the `hpke` crate.

## Notes

- **Auth mode reveals the client's identity to the relay**, since the recipient
  must know the sender's public key before decrypting. The signing variants hide
  the client identity inside the ciphertext (sign-then-encrypt).
- **ed25519 can only ever be a signing identity here** — it's not a
  Diffie–Hellman key, so it can't be an HPKE KEM key at all.

[HPKE]: https://www.rfc-editor.org/rfc/rfc9180.html
[NIP-47]: https://github.com/nostr-protocol/nips/blob/master/47.md
[X-Wing]: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
