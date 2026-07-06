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

/// Message encoding: derive per-chain verifier step counts from the message
/// via target-sum rejection sampling (the leanSig "aborting" encoding pattern).
/// Chunk c_i in [0, W) is read from an expansion digest of (msg, counter);
/// steps s_i = (W-1) - c_i; accept when sum(s_i) == TARGET_SUM.
/// Returns (steps, counter). Deterministic in msg.
pub fn encode_message<B: Backend>(msg: &Digest) -> ([usize; V_CHAINS], u32) {
    const DOMAIN: [u32; 7] = [0x6c65_616e, 0x2d78_6d73, 0x732d_656e, 0x636f_6465,
                              0x0000_0002, 0x0000_0002, 0x0000_0002];
    for ctr in 0u32..1_000_000 {
        let mut m = [0u32; 16];
        m[..8].copy_from_slice(msg);
        m[8] = ctr;
        m[9..].copy_from_slice(&DOMAIN);
        let d = B::compress(&B::iv(), &m[..8].try_into().unwrap(), &m[8..].try_into().unwrap());
        let mut steps = [0usize; V_CHAINS];
        let mut sum = 0usize;
        for (i, s) in steps.iter_mut().enumerate() {
            let chunk = ((d[i / 16] >> (2 * (i % 16))) & 3) as usize;
            *s = (W - 1) - chunk;
            sum += *s;
        }
        if sum == TARGET_SUM {
            return (steps, ctr);
        }
    }
    panic!("target-sum encoding did not converge (astronomically unlikely)");
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
    pub auth_path: [Digest; TREE_HEIGHT],
    pub path_bits: [bool; TREE_HEIGHT],
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

    Keypair { secrets, root: node, auth_path, path_bits }
}

/// Sign a message: reveal each chain at its message-derived position.
pub fn sign<B: Backend>(kp: &Keypair, msg: &Digest) -> Signature {
    let (steps, _ctr) = encode_message::<B>(msg);
    let chain_values: [Digest; V_CHAINS] = core::array::from_fn(|i| {
        let mut x = kp.secrets[i];
        for _ in 0..(W - 1 - steps[i]) {
            x = chain_step::<B>(&x);
        }
        x
    });
    Signature { chain_values, auth_path: kp.auth_path, path_bits: kp.path_bits }
}

/// Reference verification: derive steps from the message, walk chains ->
/// leaf -> path; compare to root.
pub fn verify<B: Backend>(sig: &Signature, msg: &Digest, root: &Digest) -> bool {
    let (steps, _ctr) = encode_message::<B>(msg);
    let mut tops = [[0u32; 8]; V_CHAINS];
    for (i, v) in sig.chain_values.iter().enumerate() {
        let mut x = *v;
        for _ in 0..steps[i] {
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
