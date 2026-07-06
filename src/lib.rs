//! flock-xmss: XMSS hash-based signature aggregation over standard hashes
//! (SHA-256), built on the Flock batch prover.
//!
//! Status: milestone 1 — single-signature witness mapping cross-checked
//! against the native verifier. Glue-proof wiring (chain/Merkle shift
//! sumchecks binding instance outputs to inputs) is milestone 1b.

pub mod aggregate;
pub mod backend;
pub mod glue;
pub mod native;
pub mod params;
pub mod witness;
