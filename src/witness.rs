//! Witness mapping: one XMSS verification -> an ordered list of compression
//! instances in exactly the shape Flock's setup proves, plus the wiring
//! metadata the glue sumchecks must enforce between them.
//!
//! Instance order (per signature):
//!   [chains: TARGET_SUM] [leaf: LEAF_COMPRESSIONS] [path: TREE_HEIGHT]

use crate::backend::{Backend, Digest};
use crate::native::{Signature, CHAIN_PAD};
use crate::params::*;

/// How an instance's inputs are bound — consumed by the glue proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// lo = output of instance `prev` (None = public sig value); hi = CHAIN_PAD.
    ChainStep { prev: Option<usize> },
    /// Leaf MD absorb: h = output of `prev` (None = IV); lo/hi = chain tops
    /// produced by instances `l`, `r`. `None` = a 0-step chain: the revealed
    /// signature value is absorbed directly (no producing instance).
    LeafAbsorb { prev: Option<usize>, l: Option<usize>, r: Option<usize> },
    /// Tree node: one half is output of `child`, other is the public sibling.
    PathNode { child: usize, right: bool },
}

/// Backend-agnostic record of one compression: (h, lo, hi).
pub type Triple = (Digest, Digest, Digest);

pub struct SigWitness<B: Backend> {
    /// Backend-agnostic values, used by wiring checks and glue proofs.
    pub triples: Vec<Triple>,
    /// Prover-facing instances, 1:1 with `triples`.
    pub instances: Vec<B::Instance>,
    pub wires: Vec<Wire>,
    pub computed_root: Digest,
}

/// Enumerate every compression the verifier performs, recording values AND
/// wiring. Pure function of (signature, message-derived steps, backend).
pub fn build_sig_witness<B: Backend>(sig: &Signature, steps: &[usize; V_CHAINS]) -> SigWitness<B> {
    let mut triples: Vec<Triple> = Vec::with_capacity(COMPRESSIONS_PER_SIG);
    let mut wires: Vec<Wire> = Vec::with_capacity(COMPRESSIONS_PER_SIG);
    let iv = B::iv();

    let push = |triples: &mut Vec<Triple>, h: Digest, lo: Digest, hi: Digest| -> Digest {
        triples.push((h, lo, hi));
        B::compress(&h, &lo, &hi)
    };

    // --- 1. Winternitz chains (message-derived step counts) ---
    let mut top_idx = [None; V_CHAINS]; // producing instance, None for 0-step chains
    let mut top_val = [[0u32; 8]; V_CHAINS];
    for c in 0..V_CHAINS {
        let mut x = sig.chain_values[c];
        for s in 0..steps[c] {
            let out = push(&mut triples, iv, x, CHAIN_PAD);
            wires.push(Wire::ChainStep {
                prev: if s == 0 { None } else { Some(triples.len() - 2) },
            });
            x = out;
        }
        top_idx[c] = if steps[c] > 0 { Some(triples.len() - 1) } else { None };
        top_val[c] = x;
    }

    // --- 2. Leaf: Merkle–Damgård over chain tops (2 tops / block) ---
    let mut acc = iv;
    let mut prev_leaf: Option<usize> = None;
    for pair in 0..LEAF_COMPRESSIONS {
        let (li, ri) = (top_idx[2 * pair], top_idx[2 * pair + 1]);
        let out = push(&mut triples, acc, top_val[2 * pair], top_val[2 * pair + 1]);
        wires.push(Wire::LeafAbsorb { prev: prev_leaf, l: li, r: ri });
        acc = out;
        prev_leaf = Some(triples.len() - 1);
    }

    // --- 3. Authentication path ---
    let mut node = acc;
    let mut child = triples.len() - 1;
    for lvl in 0..TREE_HEIGHT {
        let sib = sig.auth_path[lvl];
        let out = if sig.path_bits[lvl] {
            push(&mut triples, iv, sib, node)
        } else {
            push(&mut triples, iv, node, sib)
        };
        wires.push(Wire::PathNode { child, right: sig.path_bits[lvl] });
        node = out;
        child = triples.len() - 1;
    }

    debug_assert_eq!(triples.len(), COMPRESSIONS_PER_SIG);
    let instances = triples.iter().map(|(h, lo, hi)| B::instance(h, lo, hi)).collect();
    SigWitness { triples, instances, wires, computed_root: node }
}

/// Independent replay: recompute every output from its own triple and confirm
/// the wiring invariants hold value-wise. Returns the root.
pub fn replay_and_check<B: Backend>(w: &SigWitness<B>) -> Digest {
    let outs: Vec<Digest> = w.triples.iter().map(|(h, lo, hi)| B::compress(h, lo, hi)).collect();
    let iv = B::iv();

    for (i, wire) in w.wires.iter().enumerate() {
        let (h, lo, hi) = &w.triples[i];
        match *wire {
            Wire::ChainStep { prev } => {
                assert_eq!(*h, iv);
                assert_eq!(*hi, CHAIN_PAD, "chain pad must be pinned");
                if let Some(p) = prev {
                    assert_eq!(*lo, outs[p], "chain link {i} broken");
                }
            }
            Wire::LeafAbsorb { prev, l, r } => {
                match prev {
                    None => assert_eq!(*h, iv),
                    Some(p) => assert_eq!(*h, outs[p], "leaf MD link {i} broken"),
                }
                if let Some(l) = l { assert_eq!(*lo, outs[l], "leaf left top {i} broken"); }
                if let Some(r) = r { assert_eq!(*hi, outs[r], "leaf right top {i} broken"); }
            }
            Wire::PathNode { child, right } => {
                assert_eq!(*h, iv);
                let half = if right { hi } else { lo };
                assert_eq!(*half, outs[child], "path link {i} broken");
            }
        }
    }
    outs[w.triples.len() - 1]
}
