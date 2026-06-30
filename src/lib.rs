//! Shared plumbing for the `hpke-demo` / Bitcoin Wallet Connect (BWC) examples.
//!
//! - [`connect`] — the BWC connection string (`bwc://…?v=&wallet_pk=&secret=`).
//! - [`channel`] — the v1 sealing layer: X25519 HPKE in AuthPSK mode.
//! - [`rng`] — OS randomness for the `hpke` crate (rand_core 0.9 glue).
//!
//! The `bwc_basic` and `bwc_full` examples build on these modules. The other
//! examples (`alt/*`, `bwc_post_quantum_upgrade`) inline their own plumbing to
//! stay self-contained.

pub mod connect;
pub mod channel;
pub mod rng;
