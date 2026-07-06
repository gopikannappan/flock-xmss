//! Hash backend abstraction: the XMSS structure (chains, leaf, path) is
//! hash-agnostic; only the compression function and Flock setup differ.
//! Two instantiations: SHA-256 and BLAKE3, both standard battle-tested hashes.

use flock_prover::challenger::Challenger;
use flock_prover::pcs::Commitment;
use flock_prover::proof::{R1csClaim, R1csProofLigerito};

pub type Digest = [u32; 8];

pub trait Backend {
    /// Prover-facing compression instance (what `Setup::prove_fast` consumes).
    type Instance: Clone + Send + Sync;
    type Setup: Sync;
    const NAME: &'static str;

    /// Initial chaining value for fresh compressions.
    fn iv() -> Digest;
    /// One compression over two digest halves: (h, lo || hi) -> digest.
    fn compress(h: &Digest, lo: &Digest, hi: &Digest) -> Digest;
    /// Build the prover instance for the same computation.
    fn instance(h: &Digest, lo: &Digest, hi: &Digest) -> Self::Instance;

    fn setup(n_compressions: usize) -> Self::Setup;
    fn prove<Ch: Challenger>(
        setup: &Self::Setup,
        instances: &[Self::Instance],
        ch: &mut Ch,
    ) -> (R1csProofLigerito, Commitment, R1csClaim);
    fn verify<Ch: Challenger>(
        setup: &Self::Setup,
        commitment: &Commitment,
        proof: &R1csProofLigerito,
        ch: &mut Ch,
    ) -> bool;
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

pub struct Sha256Backend;

impl Backend for Sha256Backend {
    type Instance = ([u32; 8], [u32; 16]);
    type Setup = flock_prover::r1cs_hashes::sha2::Sha256HybridSetup;
    const NAME: &'static str = "sha256";

    fn iv() -> Digest {
        flock_prover::r1cs_hashes::sha2::SHA256_IV
    }
    fn compress(h: &Digest, lo: &Digest, hi: &Digest) -> Digest {
        let mut m = [0u32; 16];
        m[..8].copy_from_slice(lo);
        m[8..].copy_from_slice(hi);
        flock_prover::r1cs_hashes::sha2::sha256_compress(h, &m)
    }
    fn instance(h: &Digest, lo: &Digest, hi: &Digest) -> Self::Instance {
        let mut m = [0u32; 16];
        m[..8].copy_from_slice(lo);
        m[8..].copy_from_slice(hi);
        (*h, m)
    }
    fn setup(n: usize) -> Self::Setup {
        flock_prover::r1cs_hashes::sha2::Sha256HybridSetup::new(n)
    }
    fn prove<Ch: Challenger>(
        s: &Self::Setup,
        inst: &[Self::Instance],
        ch: &mut Ch,
    ) -> (R1csProofLigerito, Commitment, R1csClaim) {
        s.prove_fast(inst, ch)
    }
    fn verify<Ch: Challenger>(
        s: &Self::Setup,
        c: &Commitment,
        p: &R1csProofLigerito,
        ch: &mut Ch,
    ) -> bool {
        s.verify(c, p, ch).is_ok()
    }
}

// ---------------------------------------------------------------------------
// BLAKE3
// ---------------------------------------------------------------------------

/// Fixed BLAKE3 domain constants for our single-block compressions:
/// full 64-byte block, standalone (CHUNK_START | CHUNK_END | ROOT = 1|2|8).
pub const B3_BLOCK_LEN: u32 = 64;
pub const B3_FLAGS: u32 = 11;

pub struct Blake3Backend;

impl Backend for Blake3Backend {
    type Instance = ([u32; 8], [u32; 16], u64, u32, u32);
    type Setup = flock_prover::r1cs_hashes::blake3::Blake3Setup;
    const NAME: &'static str = "blake3";

    fn iv() -> Digest {
        flock_prover::r1cs_hashes::blake3::BLAKE3_IV
    }
    fn compress(h: &Digest, lo: &Digest, hi: &Digest) -> Digest {
        let mut m = [0u32; 16];
        m[..8].copy_from_slice(lo);
        m[8..].copy_from_slice(hi);
        let out =
            flock_prover::r1cs_hashes::blake3::blake3_compress(h, &m, 0, B3_BLOCK_LEN, B3_FLAGS);
        out[..8].try_into().unwrap()
    }
    fn instance(h: &Digest, lo: &Digest, hi: &Digest) -> Self::Instance {
        let mut m = [0u32; 16];
        m[..8].copy_from_slice(lo);
        m[8..].copy_from_slice(hi);
        (*h, m, 0, B3_BLOCK_LEN, B3_FLAGS)
    }
    fn setup(n: usize) -> Self::Setup {
        flock_prover::r1cs_hashes::blake3::Blake3Setup::new(n)
    }
    fn prove<Ch: Challenger>(
        s: &Self::Setup,
        inst: &[Self::Instance],
        ch: &mut Ch,
    ) -> (R1csProofLigerito, Commitment, R1csClaim) {
        s.prove_fast(inst, ch)
    }
    fn verify<Ch: Challenger>(
        s: &Self::Setup,
        c: &Commitment,
        p: &R1csProofLigerito,
        ch: &mut Ch,
    ) -> bool {
        s.verify(c, p, ch).is_ok()
    }
}
