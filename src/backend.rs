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
    /// Setup at the conservative 120-bit `Secure` Ligerito profile (unique
    /// decoding, rate 1/2) instead of the default 100-bit `Fast` profile.
    fn setup_secure(n_compressions: usize) -> Self::Setup;
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

    // ---- Glue-side geometry (used by the sound wiring sumcheck) ----
    /// log2 of the number of 256-bit slots addressed by the wiring cube.
    /// 2 for SHA (4 core slots); 3 for BLAKE3 (4 core + 1 domain, padded to 8).
    const N_SLOTS_LOG: usize;
    /// Byte offset of each core 256-bit slot within a block:
    /// [H_in, H_out, M_lo, M_hi]. Both backends: [0, 32, 64, 96].
    fn slot_byte_offsets() -> [usize; 4];
    /// Physical within-slot bit layout of a public digest (matches the
    /// setup's witness generator), for folding public endpoints.
    fn digest_to_phys_bits(d: &Digest) -> Vec<bool>;
    /// Optional domain slot that must be pinned to a constant every block:
    /// (slot_index, byte_offset, phys_bits_of_the_constant). BLAKE3 pins its
    /// counter/block_len/flags/z-const slot; SHA has no domain fields.
    fn domain_slot() -> Option<(usize, usize, Vec<bool>)> {
        None
    }
    fn k_log(setup: &Self::Setup) -> usize;
    fn m(setup: &Self::Setup) -> usize;
    fn r1cs(setup: &Self::Setup) -> &flock_prover::r1cs::BlockR1cs;
    fn pcs_params(setup: &Self::Setup) -> &flock_prover::pcs::PcsParams;
    /// Generate the packed (z, a, b, z_lincheck) witness for the batch.
    fn gen_witness_ab(
        instances: &[Self::Instance],
        n_blocks_log: usize,
    ) -> (
        Vec<flock_prover::field::F128>,
        Vec<flock_prover::field::F128>,
        Vec<flock_prover::field::F128>,
        Vec<u8>,
    );
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
    fn setup_secure(n: usize) -> Self::Setup {
        flock_prover::r1cs_hashes::sha2::Sha256HybridSetup::with_profile(
            n,
            flock_prover::pcs::ligerito::LigeritoProfile::Secure,
        )
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

    const N_SLOTS_LOG: usize = 2;
    fn slot_byte_offsets() -> [usize; 4] { [0, 32, 64, 96] }
    fn digest_to_phys_bits(d: &Digest) -> Vec<bool> {
        flock_prover::r1cs_hashes::sha2::cv_to_phys_bits(d)
    }
    fn k_log(s: &Self::Setup) -> usize { s.r1cs.k_log }
    fn m(s: &Self::Setup) -> usize { s.r1cs.m }
    fn r1cs(s: &Self::Setup) -> &flock_prover::r1cs::BlockR1cs { &s.r1cs }
    fn pcs_params(s: &Self::Setup) -> &flock_prover::pcs::PcsParams { &s.pcs_params }
    fn gen_witness_ab(
        inst: &[Self::Instance],
        n_log: usize,
    ) -> (Vec<flock_prover::field::F128>, Vec<flock_prover::field::F128>, Vec<flock_prover::field::F128>, Vec<u8>) {
        flock_prover::r1cs_hashes::sha2::generate_witness_with_ab_packed_and_lincheck(inst, n_log)
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
    fn setup_secure(n: usize) -> Self::Setup {
        flock_prover::r1cs_hashes::blake3::Blake3Setup::with_profile(
            n,
            flock_prover::pcs::ligerito::LigeritoProfile::Secure,
        )
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

    const N_SLOTS_LOG: usize = 3; // 4 core + 1 domain slot, cube padded to 8
    fn slot_byte_offsets() -> [usize; 4] { [0, 32, 64, 96] }
    fn digest_to_phys_bits(d: &Digest) -> Vec<bool> {
        flock_prover::r1cs_hashes::blake3::cv_to_phys_bits(d)
    }
    fn domain_slot() -> Option<(usize, usize, Vec<bool>)> {
        // The domain slot [T_LO_BASE, GS_BASE) = byte 128, holding, LSB-first
        // per 32-bit word: t_lo=0, t_hi=0, block_len=64, flags=11, then the
        // z-constant bit = 1, then zero padding. Every block must carry exactly
        // these bits (our fixed single-block domain), so pinning the whole
        // slot to this constant enforces the correct BLAKE3 domain.
        let mut phys = vec![false; 256];
        let put_word = |phys: &mut [bool], word_idx: usize, val: u32| {
            for b in 0..32 {
                phys[32 * word_idx + b] = (val >> b) & 1 == 1;
            }
        };
        put_word(&mut phys, 0, 0);  // counter_low
        put_word(&mut phys, 1, 0);  // counter_high
        put_word(&mut phys, 2, B3_BLOCK_LEN); // 64
        put_word(&mut phys, 3, B3_FLAGS);     // 11
        phys[128] = true;           // z-constant
        Some((4, 128, phys))        // slot index 4, byte offset 128
    }
    fn k_log(s: &Self::Setup) -> usize { s.r1cs.k_log }
    fn m(s: &Self::Setup) -> usize { s.r1cs.m }
    fn r1cs(s: &Self::Setup) -> &flock_prover::r1cs::BlockR1cs { &s.r1cs }
    fn pcs_params(s: &Self::Setup) -> &flock_prover::pcs::PcsParams { &s.pcs_params }
    fn gen_witness_ab(
        inst: &[Self::Instance],
        n_log: usize,
    ) -> (Vec<flock_prover::field::F128>, Vec<flock_prover::field::F128>, Vec<flock_prover::field::F128>, Vec<u8>) {
        flock_prover::r1cs_hashes::blake3::generate_witness_with_ab_packed_and_lincheck(inst, n_log)
    }
}
