//! Native (non-SNARK) XMSS reference implementation — the correctness oracle.
//! Generic over the hash backend; uses Flock's own compression functions so
//! the witness mapping is bit-identical by construction.

use crate::backend::{Backend, Digest};
use crate::params::*;

/// Domain-separation constant filling the unused half of a chain-step block.
pub const CHAIN_PAD: Digest = [
    0x666c_6f63, 0x6b2d_786d, 0x7373_2d63, 0x6861_696e, // "flock-xmss-chain"
    0x0000_0001, 0x0000_0001, 0x0000_0001, 0x0000_0001,
];

/// One Winternitz chain step: x -> compress(IV, x || CHAIN_PAD).
pub fn chain_step<B: Backend>(x: &Digest) -> Digest {
    B::compress(&B::iv(), x, &CHAIN_PAD)
}

/// 2-to-1 tree compression: (l, r) -> compress(IV, l || r).
pub fn node_hash<B: Backend>(l: &Digest, r: &Digest) -> Digest {
    B::compress(&B::iv(), l, r)
}

/// Leaf = Merkle–Damgård over the V chain tops (2 tops / compression).
pub fn leaf_hash<B: Backend>(tops: &[Digest; V_CHAINS]) -> Digest {
    let mut acc = B::iv();
    for pair in tops.chunks(2) {
        acc = B::compress(&acc, &pair[0], &pair[1]);
    }
    acc
}

/// Deterministic test rng (same splitmix64 pattern as flock's benches).
pub struct Rng(pub u64);
impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn digest(&mut self) -> Digest {
        core::array::from_fn(|_| self.next_u64() as u32)
    }
    pub fn bit(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

/// A signature plus everything the verifier needs.
pub struct Signature {
    /// Revealed chain values (position `W-1-chain_steps(i)` of each chain).
    pub chain_values: [Digest; V_CHAINS],
    /// Auth-path siblings, leaf level first.
    pub auth_path: [Digest; TREE_HEIGHT],
    /// Direction bits: `true` = our node is the RIGHT child at that level.
    pub path_bits: [bool; TREE_HEIGHT],
}

pub struct Keypair {
    pub secrets: [Digest; V_CHAINS],
    pub root: Digest,
    pub sig_template: Signature,
}

/// Deterministic keygen for ONE one-time key + its auth path (siblings are
/// random digests — only the path matters to the verifier, mirroring flock's
/// `honest_merkle_path` bench construction).
pub fn keygen<B: Backend>(seed: u64) -> Keypair {
    let mut rng = Rng(seed);
    let secrets: [Digest; V_CHAINS] = core::array::from_fn(|_| rng.digest());

    // Chain tops: W-1 steps from each secret.
    let mut tops = [[0u32; 8]; V_CHAINS];
    for (i, s) in secrets.iter().enumerate() {
        let mut x = *s;
        for _ in 0..(W - 1) {
            x = chain_step::<B>(&x);
        }
        tops[i] = x;
    }
    let leaf = leaf_hash::<B>(&tops);

    // Auth path with random siblings.
    let auth_path: [Digest; TREE_HEIGHT] = core::array::from_fn(|_| rng.digest());
    let path_bits: [bool; TREE_HEIGHT] = core::array::from_fn(|_| rng.bit());
    let mut node = leaf;
    for lvl in 0..TREE_HEIGHT {
        node = if path_bits[lvl] {
            node_hash::<B>(&auth_path[lvl], &node)
        } else {
            node_hash::<B>(&node, &auth_path[lvl])
        };
    }

    // Reveal position W-1-chain_steps(i) of each chain.
    let chain_values: [Digest; V_CHAINS] = core::array::from_fn(|i| {
        let mut x = secrets[i];
        for _ in 0..(W - 1 - chain_steps(i)) {
            x = chain_step::<B>(&x);
        }
        x
    });

    Keypair {
        secrets,
        root: node,
        sig_template: Signature { chain_values, auth_path, path_bits },
    }
}

/// Reference verification: walk chains -> leaf -> path; compare to root.
pub fn verify<B: Backend>(sig: &Signature, root: &Digest) -> bool {
    let mut tops = [[0u32; 8]; V_CHAINS];
    for (i, v) in sig.chain_values.iter().enumerate() {
        let mut x = *v;
        for _ in 0..chain_steps(i) {
            x = chain_step::<B>(&x);
        }
        tops[i] = x;
    }
    let mut node = leaf_hash::<B>(&tops);
    for lvl in 0..TREE_HEIGHT {
        node = if sig.path_bits[lvl] {
            node_hash::<B>(&sig.auth_path[lvl], &node)
        } else {
            node_hash::<B>(&node, &sig.auth_path[lvl])
        };
    }
    node == *root
}
