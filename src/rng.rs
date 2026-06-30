//! OS randomness for the `hpke` crate.
//!
//! [`OsRng`] is the `rand_core` 0.9 glue the `hpke` crate's API requires —
//! boilerplate unrelated to HPKE itself, factored out so the examples don't
//! repeat it.

use hpke::rand_core::{CryptoRng, RngCore};

/// An OS-seeded CSPRNG implementing `hpke`'s `rand_core` 0.9 traits.
pub struct OsRng;

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
}

/// Generate `N` random bytes from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS RNG failure");
    out
}
