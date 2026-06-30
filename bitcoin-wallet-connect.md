# Bitcoin Wallet Connect (BWC)

**Draft — beginnings only.** A message-passing RPC between a **client** and a
**wallet** through an **untrusted relay**, with end-to-end confidentiality and
mutual authentication via HPKE ([RFC 9180]). Bootstraps from a NIP-47-style
connection string. Runnable prototypes live in this repo's `examples/`.

This document pins down everything BWC does *around* HPKE — the pieces a
second implementation (in Go, say) needs beyond a conformant HPKE library:
the connection string, the trust model, exactly how the HPKE primitives are
parameterized, and the wire framing. Everything inside HPKE (KEM math, key
schedule, AEAD) is delegated to [RFC 9180] and not restated here.

## Roles & trust model

- **Client** — the app driving the wallet (e.g. an LN app). Holds a
  per-connection X25519 static key; `client_pk` is registered with the wallet
  out of band (bootstrap — see TODO).
- **Wallet** — the signer/authority. Holds a per-connection X25519 static key;
  `wallet_pk` reaches the client inside the trusted connection string.
- **Relay** — untrusted transport between client and wallet. Sees ciphertext
  and routing metadata only; never plaintext and never any private key. Access
  to it may be gated by a bearer `token` (see [Relay authentication]). Since
  every message is an independent sealed blob, the transport model is the
  implementer's choice — a synchronous proxy (as in `bwc_full`) or a
  store-and-forward mailbox — and BWC requires neither.
- **`secret`** — a high-entropy value shared by client and wallet, carried in
  the connection string and used as the HPKE PSK. A bearer credential: one per
  authorization grant, rotate to revoke.

Authentication is mutual and two-factor: a peer is authentic only if it holds
**both** the connection `secret` (PSK) **and** the expected static private key
(bound into the KEM via HPKE's Auth mode).

## Connection string

The wallet hands the client a connection string (QR, deeplink, or paste):

```
bwc://<relay>?v=<version>&wallet_pk=<hex>&secret=<hex>[&token=<token>][&<relay-param>=<value>…]
```

| Param | Meaning |
|-------|---------|
| `v` | Protocol version (decimal). Parsed **first**; unknown versions are hard-rejected. The seam that lets the crypto suite be upgraded later — including to post-quantum — without changing the string format. |
| `wallet_pk` | The wallet's KEM public key: HPKE recipient key and trust anchor. Its type is version-defined (v1: a 32-byte X25519 key). |
| `secret` | The connection secret / HPKE PSK. ≥128 bits of entropy. |
| `token` | *(optional)* Bearer credential authenticating the client to the relay. Opaque to BWC; see [Relay authentication]. |

Encoding rules:

- `<relay>` is an opaque `host[:port][/path]` the client uses as transport.
- `wallet_pk` and `secret` are lowercase hex of their raw bytes.
- Params are order-independent. `v` is parsed first; it gates everything
  version-typed.
- `token`, if present, MUST be stripped from the URL by the client and sent as
  an `Authorization: Bearer <token>` header instead (see [Relay authentication])
  — never left in the query string, so it stays out of the URL logs proxies and
  servers routinely keep.
- Any param the client doesn't recognize is **forwarded to the relay** verbatim
  on each request (the relay may key routing or policy off it), rather than
  dropped.

## Relay authentication (optional)

The HPKE layer authenticates the *client to the wallet* end-to-end, but says
nothing about who may reach the relay. A relay is the entry point that can wake
or reach a wallet — a self-custodial mobile wallet, say, whose relay pushes to
the user's phone. Its operator usually wants to admit only authorized clients,
to keep strangers from spamming that path.

BWC supports this with one optional connection-string param, `token`, and one
rule: **if the string carries a `token`, the client strips it from the URL and
sends it as an `Authorization: Bearer <token>` header on every request to the
relay.** Keeping it in a header rather than the query string keeps the credential
out of the URL logs that proxies and servers routinely keep.

Everything else about the token is out of BWC's scope. It is an **opaque bearer
credential**: the wallet's vendor issues it (e.g. after the user authenticates
in-app) and the vendor's relay verifies it; BWC never inspects it. Vendors pick
their own scheme — a signed JWT, a macaroon, or (as in `bwc_full`) a random
capability string the relay mints and remembers, valid only for the one
connection it was issued for. **No scheme is part of BWC** and no conformant
relay need understand any particular one.

This client↔relay check is orthogonal to the client↔wallet mutual authentication
of the HPKE layer: one gates access to the transport, the other provides
end-to-end confidentiality and authenticity. A relay that admits a request still
cannot read or forge it.

## Cryptographic construction — v1

Each request and each response is an **independent one-shot** HPKE context; no
state is persisted or ratcheted between messages. v1 uses HPKE in **AuthPSK**
mode with this suite:

| Component | RFC 9180 codepoint | Value |
|-----------|--------------------|-------|
| Mode | `0x03` | `mode_auth_psk` |
| KEM | `0x0020` | DHKEM(X25519, HKDF-SHA256) |
| KDF | `0x0001` | HKDF-SHA256 |
| AEAD | `0x0003` | ChaCha20Poly1305 |

Sealing/opening use the RFC 9180 §6.1 single-shot API, `SealAuthPSK` /
`OpenAuthPSK`, parameterized per direction:

| | Request (client → wallet) | Response (wallet → client) |
|---|---|---|
| `info` | `"bwc-v1 request"` | `"bwc-v1 response"` |
| recipient `pkR` / `skR` | `wallet_pk` | `client_pk` |
| sender `skS` / `pkS` | client static key | wallet static key |
| `psk` | connection `secret` | connection `secret` |
| `psk_id` | `"bwc-connection"` | `"bwc-connection"` |
| `aad` | *(empty)* | *(empty)* |

The `info` and `psk_id` values are exact ASCII byte strings (no NUL, no length
prefix). The distinct `info` per direction stops a message from being replayed
back along the other direction.

## Wire format

A sealed message on the wire is the encapsulated key concatenated with the
AEAD ciphertext:

```
message = enc || ct
```

For the v1 suite:

- `enc` — 32 bytes. The X25519 encapsulated key (`Nenc`), raw RFC 7748
  encoding — the same encoding used for `wallet_pk` in the connection string.
- `ct` — `len(plaintext) + 16` bytes: the AEAD output including
  ChaCha20Poly1305's 16-byte tag (`Nt`).

The receiver splits the first 32 bytes as `enc` and opens the remainder.

**Plaintext framing (replay-protected, provisional).** `bwc_full` frames the
plaintext — the bytes fed to `SealAuthPSK` — as:

```
plaintext = nonce(16) || timestamp(8) || body
```

- `nonce` — 16 fresh random bytes, unique per request.
- `timestamp` — big-endian `u64`, unix seconds at send time.
- `body` — the RPC payload (**not yet specified**; see TODO).

The wallet, trusting only its own clock, rejects a request whose `timestamp`
is more than **300 s** (`MAX_CLOCK_SKEW_SECS`) from `now`, and rejects any
`nonce` already seen this session. Cache entries expire after `2 × 300 s` — the
widest window in which a captured request could still pass the freshness check.
Because `nonce` and `timestamp` sit inside the sealed plaintext, both are
authenticated by the AEAD.

## Versioning & post-quantum upgrade

`v` is the upgrade seam. A client parses `v` before anything version-typed and
hard-rejects unknown versions, so a wallet can advertise a stronger suite
without breaking older clients. `examples/bwc_post_quantum_upgrade.rs` sketches
v2: the KEM becomes **X-Wing** (X25519 + ML-KEM-768), giving a larger
`wallet_pk` / `enc`. X-Wing is not an HPKE KEM (RFC 9180 defines none — it's
`draft-ietf-hpke-pq`), so v2 runs an HPKE-shaped `encapsulate → HKDF-SHA256 →
ChaCha20Poly1305` schedule by hand. It also drops the KEM's static-key binding
(X-Wing has no Auth mode), leaving the `secret` as the sole client
authenticator — authentication rides the PSK, not the KEM, so it survives the
swap.

## Reference implementations

- [`examples/bwc_basic.rs`](examples/bwc_basic.rs) — minimal client ⇄ wallet
  round trip.
- [`examples/bwc_full.rs`](examples/bwc_full.rs) — replay-protected wallet
  server behind a real axum relay that authenticates the client (bearer token)
  and proxies to it (reqwest client).
- [`examples/bwc_post_quantum_upgrade.rs`](examples/bwc_post_quantum_upgrade.rs)
  — the versioned + post-quantum form.
- [`src/`](src/) — the shared connection-string and v1 sealing layer that
  `bwc_basic` and `bwc_full` build on.

## TODO — not yet specified

- **RPC `body` framing** — request id, method, params, expiry, and the response
  framing. The next thing to pin down.
- Bootstrap: how the client registers `client_pk` with the wallet.
- Relay semantics: the routing token that addresses a wallet, and — for
  store-and-forward relays — mailbox retention and push-wake signaling.
- v2 suite (X-Wing) parameters; capability descriptor; key rotation.

[Relay authentication]: #relay-authentication-optional
[RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html
