//! XMSS parameter set — milestone-1 "fixed-work" variant.
//!
//! DKKW25-style hash-based multisig verification is dominated by:
//!   1. Winternitz chains: `V` chains of length `W`; the verifier walks each
//!      chain from the signature value up to the chain top.
//!   2. Leaf compression: hash all chain tops into the OTS leaf.
//!   3. Merkle authentication path: `TREE_HEIGHT` 2-to-1 compressions to the
//!      public root.
//!
//! Milestone-1 simplification (clearly labeled, cost-faithful): the per-chain
//! start position is FIXED at `CHAIN_STEPS` (mid-chain) instead of
//! message-dependent. DKKW25's target-sum encoding makes total chain work
//! constant anyway; making each chain's work constant too lets every chain map
//! onto Flock's uniform instance batch. Message-dependent positions are
//! milestone 2 (selector logic in the glue circuit).
//!
//! All hashing is the SHA-256 compression function `compress(h, m)`:
//! 256-bit chaining value + 512-bit message block -> 256-bit output —
//! exactly the instance Flock's `Sha256HybridSetup` proves.

/// Number of Winternitz chains per signature (encodes a 256-bit digest,
/// ~4 bits/chain in DKKW25-style parameterizations).
pub const V_CHAINS: usize = 66;

/// Chain length (w). Verifier walks `CHAIN_STEPS` of the `W - 1` total steps.
pub const W: usize = 4;

/// Fixed number of compression calls the verifier does per chain (milestone-1
/// fixed-position variant; = the average of a target-sum encoding).
pub const TARGET_SUM: usize = 117;

/// Per-chain verifier steps (fixed pattern summing to TARGET_SUM; the real
/// scheme derives these from the message hash - milestone 2). 51 chains do
/// 2 steps, 15 chains do 1 step: 51*2 + 15*1 = 117.
pub const fn chain_steps(c: usize) -> usize { if c < 51 { 2 } else { 1 } }

/// Merkle tree height (number of auth-path compressions). 2^13 = 8192
/// one-time keys per public root — leanSig-scale.
pub const TREE_HEIGHT: usize = 18;

/// Compressions to fold `V_CHAINS` 256-bit chain tops into the 256-bit leaf:
/// Merkle-Damgård over V*256 bits of message, 512 bits per compression.
pub const LEAF_COMPRESSIONS: usize = V_CHAINS * 256 / 512; // 33

/// Total SHA-256 compressions per signature verification.
pub const COMPRESSIONS_PER_SIG: usize = TARGET_SUM // 117
    + LEAF_COMPRESSIONS                              // 33
    + TREE_HEIGHT;                                   // 18 => 168

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts() {
        assert_eq!(LEAF_COMPRESSIONS, 33);
        assert_eq!(COMPRESSIONS_PER_SIG, 168);
        let ts: usize = (0..V_CHAINS).map(chain_steps).sum();
        assert_eq!(ts, TARGET_SUM);
        assert!(chain_steps(0) < W && chain_steps(V_CHAINS-1) < W);
    }
}
