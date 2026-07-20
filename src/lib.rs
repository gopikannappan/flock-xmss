//! flock-xmss: XMSS hash-based signature aggregation over standard hashes
//! (SHA-256), built on the Flock batch prover.
//!
//! Status: milestone 1 — single-signature witness mapping cross-checked
//! against the native verifier. Glue-proof wiring (chain/Merkle shift
//! sumchecks binding instance outputs to inputs) is milestone 1b.

pub mod aggregate;
pub mod backend;
pub mod glue;
pub mod hiding;
pub mod glue_hidden;
pub mod native;
pub mod params;
pub mod witness;

// zkVM-safe Instant: real std::time on the host, a no-op stub inside the SP1 zkVM
// (which has no clock). flock's profiling timers route through this.
pub mod ztime {
    #[cfg(not(target_os = "zkvm"))]
    pub use std::time::Instant;

    #[cfg(target_os = "zkvm")]
    #[derive(Clone, Copy)]
    pub struct Instant;

    #[cfg(target_os = "zkvm")]
    impl Instant {
        #[inline]
        pub fn now() -> Self { Self }
        #[inline]
        pub fn elapsed(&self) -> core::time::Duration { core::time::Duration::ZERO }
    }
}
