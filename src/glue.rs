//! Linkage glue (milestone 1b step 2): makes the aggregate proof SOUND by
//! enforcing the wiring between compression instances.
//!
//! Design ("wiring sumcheck"): after the base R1CS proof, each instance's four
//! 256-bit slots (H, OUT, LO, HI) are folded to per-instance scalars at a
//! verifier point tau_pos (reusing flock's `ChainFold`). Every wiring
//! constraint from `witness::Wire` becomes a scalar equation:
//!
//!   Link:  G[sx][i] + G[sy][j]        = 0   (char 2: equality)
//!   Pin:   G[sx][i] + fold(constant)  = 0   (IV, CHAIN_PAD)
//!   Root:  G[OUT][last_i] + fold(root) = 0  (public per-signature roots)
//!
//! The verifier samples one scalar rho; all equations combine with geometric
//! coefficients rho^e into ONE claim  sum_{s,i} W[s][i]*G[s][i] = RHS, where W
//! is a public weight table and RHS collects the constant/root terms. A
//! degree-2 paired-fold sumcheck over the (slot, instance) cube reduces this
//! to a single MLE evaluation of the committed witness, which joins the
//! batched PCS opening (BaseFold mixed path, as in `prove_chain_generic`).
//!
//! Soundness: RLC error #equations/|F|; the final claim is bound by the PCS.
//! The verifier does O(#equations) field work to build W and RHS — linear in
//! batch size with a tiny constant, while proof SIZE stays succinct.
//!
//! SHA-256 backend only: its witness has four aligned 256-bit slots at bytes
//! 0/32/64/96 (H_in, H_out, M_lo, M_hi). BLAKE3's M region starts at bit 513
//! (not slot-aligned) and needs a bit-offset fold — future work.

use flock_prover::challenger::Challenger;
use flock_prover::field::F128;
use flock_prover::lincheck::QuirkyPoint;
use flock_prover::pcs::Commitment;
use flock_prover::r1cs_hashes::chain_common::{fold_in_out, ChainFold, ChainLayout};
use flock_prover::r1cs_hashes::sha2::{
    cv_to_phys_bits, generate_witness_with_ab_packed_and_lincheck, Sha256HybridSetup, SHA256_IV,
};

use crate::backend::{Digest, Sha256Backend};
use crate::native::{Signature, CHAIN_PAD};
use crate::params::*;
use crate::witness::build_sig_witness;

const N_SLOTS_LOG: usize = 2; // 4 slots: H=0, OUT=1, LO=2, HI=3
const SLOT_H: usize = 0;
const SLOT_OUT: usize = 1;
const SLOT_LO: usize = 2;
const SLOT_HI: usize = 3;
/// Placeholder slot for path links; resolved by the public path bit.
const SLOT_BY_PATH_BIT: usize = usize::MAX;

/// SHA-256 slot geometry as two flock ChainLayouts (reusing their fold math).
fn layout_pair(k_log: usize) -> (ChainLayout, ChainLayout) {
    let mk = |in_off: usize, out_off: usize| ChainLayout {
        k_log,
        k_skip: 6,
        region_log: 8,
        region_bits: 256,
        input_byte_off: in_off,
        output_byte_off: out_off,
    };
    (mk(0, 32), mk(64, 96)) // (H, OUT), (LO, HI)
}

/// `x_outer_full` from a QuirkyPoint (inline of flock's pub(crate) helper:
/// concat x_inner_rest ++ x_outer).
fn x_outer_full(p: &QuirkyPoint) -> Vec<F128> {
    let mut v = Vec::with_capacity(p.x_inner_rest.len() + p.x_outer.len());
    v.extend_from_slice(&p.x_inner_rest);
    v.extend_from_slice(&p.x_outer);
    v
}

// ---------------------------------------------------------------------------
// Wiring specification
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Eq {
    Link { xs: usize, xi: usize, ys: usize, yi: usize },
    Pin { xs: usize, xi: usize, konst: usize }, // 0 = IV, 1 = CHAIN_PAD
    Root { xi: usize, sig: usize },
}

/// Deterministic wiring for K signatures, driven by the message-derived
/// per-chain step counts (mirrors witness::build_sig_witness).
fn wiring(steps_per_sig: &[[usize; V_CHAINS]]) -> Vec<Eq> {
    let mut eqs = Vec::new();
    for (sig, steps) in steps_per_sig.iter().enumerate() {
        let base = sig * COMPRESSIONS_PER_SIG;
        let mut idx = base;
        let mut top_idx = [None; V_CHAINS];
        for c in 0..V_CHAINS {
            for s in 0..steps[c] {
                if s > 0 {
                    eqs.push(Eq::Link { xs: SLOT_LO, xi: idx, ys: SLOT_OUT, yi: idx - 1 });
                }
                eqs.push(Eq::Pin { xs: SLOT_HI, xi: idx, konst: 1 });
                eqs.push(Eq::Pin { xs: SLOT_H, xi: idx, konst: 0 });
                idx += 1;
            }
            top_idx[c] = if steps[c] > 0 { Some(idx - 1) } else { None };
        }
        for j in 0..LEAF_COMPRESSIONS {
            if j == 0 {
                eqs.push(Eq::Pin { xs: SLOT_H, xi: idx, konst: 0 });
            } else {
                eqs.push(Eq::Link { xs: SLOT_H, xi: idx, ys: SLOT_OUT, yi: idx - 1 });
            }
            if let Some(t) = top_idx[2 * j] {
                eqs.push(Eq::Link { xs: SLOT_LO, xi: idx, ys: SLOT_OUT, yi: t });
            }
            if let Some(t) = top_idx[2 * j + 1] {
                eqs.push(Eq::Link { xs: SLOT_HI, xi: idx, ys: SLOT_OUT, yi: t });
            }
            idx += 1;
        }
        for _l in 0..TREE_HEIGHT {
            eqs.push(Eq::Pin { xs: SLOT_H, xi: idx, konst: 0 });
            eqs.push(Eq::Link { xs: SLOT_BY_PATH_BIT, xi: idx, ys: SLOT_OUT, yi: idx - 1 });
            idx += 1;
        }
        eqs.push(Eq::Root { xi: idx - 1, sig });
    }
    eqs
}

/// Build the weight tables W[4][2^n_log] and the constant RHS. `path_bit`
/// resolves the placeholder slots from the public per-signature bits.
fn build_w(
    eqs: &[Eq],
    rho: F128,
    n_log: usize,
    iv_fold: F128,
    pad_fold: F128,
    root_folds: &[F128],
    path_bit: &dyn Fn(usize, usize) -> bool,
) -> (Vec<Vec<F128>>, F128) {
    let n = 1usize << n_log;
    let mut w = vec![vec![F128::ZERO; n]; 4];
    let mut rhs = F128::ZERO;
    let mut coef = F128::ONE;
    let mut path_lvl = vec![0usize; root_folds.len()];
    for eq in eqs {
        match *eq {
            Eq::Link { xs, xi, ys, yi } => {
                let xs = if xs == SLOT_BY_PATH_BIT {
                    let sig = xi / COMPRESSIONS_PER_SIG;
                    let lvl = path_lvl[sig];
                    path_lvl[sig] += 1;
                    if path_bit(sig, lvl) { SLOT_HI } else { SLOT_LO }
                } else {
                    xs
                };
                w[xs][xi] += coef;
                w[ys][yi] += coef; // char 2: subtraction == addition
            }
            Eq::Pin { xs, xi, konst } => {
                w[xs][xi] += coef;
                rhs += coef * if konst == 0 { iv_fold } else { pad_fold };
            }
            Eq::Root { xi, sig } => {
                w[SLOT_OUT][xi] += coef;
                rhs += coef * root_folds[sig];
            }
        }
        coef *= rho;
    }
    (w, rhs)
}

// ---------------------------------------------------------------------------
// Paired-fold degree-2 sumcheck (explicit tables W, G; LSB-first rounds)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
pub struct WiringProof {
    pub rounds: Vec<(F128, F128)>, // (q(1), q(inf)) per round
    pub g_at_point: F128,
}

fn sumcheck_prove<Ch: Challenger>(
    mut w: Vec<F128>,
    mut g: Vec<F128>,
    ch: &mut Ch,
) -> (WiringProof, Vec<F128>) {
    let v = w.len().trailing_zeros() as usize;
    let mut rounds = Vec::with_capacity(v);
    let mut point = Vec::with_capacity(v);
    for _ in 0..v {
        let half = w.len() / 2;
        let mut q1 = F128::ZERO;
        let mut qi = F128::ZERO;
        for j in 0..half {
            let (w0, w1) = (w[2 * j], w[2 * j + 1]);
            let (g0, g1) = (g[2 * j], g[2 * j + 1]);
            q1 += w1 * g1;
            qi += (w1 + w0) * (g1 + g0); // char 2 differences
        }
        ch.observe_f128(q1);
        ch.observe_f128(qi);
        let r = ch.sample_f128();
        for j in 0..half {
            w[j] = w[2 * j] + r * (w[2 * j + 1] + w[2 * j]);
            g[j] = g[2 * j] + r * (g[2 * j + 1] + g[2 * j]);
        }
        w.truncate(half);
        g.truncate(half);
        point.push(r);
        rounds.push((q1, qi));
    }
    (WiringProof { rounds, g_at_point: g[0] }, point)
}

fn sumcheck_verify<Ch: Challenger>(
    proof: &WiringProof,
    claim: F128,
    ch: &mut Ch,
) -> (Vec<F128>, F128) {
    let mut c = claim;
    let mut point = Vec::with_capacity(proof.rounds.len());
    for &(q1, qi) in &proof.rounds {
        // q(X) = qi*X^2 + b*X + q0 with q0 = c + q1 (q(0)+q(1) = c in char 2).
        let q0 = c + q1;
        let b = q1 + q0 + qi;
        ch.observe_f128(q1);
        ch.observe_f128(qi);
        let r = ch.sample_f128();
        c = qi * r * r + b * r + q0;
        point.push(r);
    }
    (point, c)
}

/// MLE of an explicit table at `point` (LSB-first) by in-place folding.
fn mle_eval(table: &[F128], point: &[F128]) -> F128 {
    let mut t = table.to_vec();
    for r in point {
        let half = t.len() / 2;
        for j in 0..half {
            t[j] = t[2 * j] + *r * (t[2 * j + 1] + t[2 * j]);
        }
        t.truncate(half);
    }
    t[0]
}

// ---------------------------------------------------------------------------
// Sound aggregation (SHA-256, BaseFold mixed opening)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
pub struct SoundAggregateProof {
    pub zerocheck: flock_prover::zerocheck::ZerocheckProof,
    pub lincheck: flock_prover::lincheck::LincheckProof,
    pub wiring: WiringProof,
    pub pcs_open: flock_prover::pcs::BatchOpeningProofLigerito,
    pub commitment: Commitment,
    pub n_signatures: usize,
}

/// Prove K signature verifications with full wiring enforcement.
/// Statement: (roots, path_bits) per signature; signatures are witness.
pub fn prove_sound<Ch: Challenger>(
    setup: &Sha256HybridSetup,
    sigs: &[Signature],
    msgs: &[Digest],
    ch: &mut Ch,
) -> SoundAggregateProof {
    assert_eq!(sigs.len(), msgs.len());
    let steps: Vec<[usize; V_CHAINS]> = msgs
        .iter()
        .map(|m| crate::native::encode_message::<Sha256Backend>(m).0)
        .collect();
    let mut instances = Vec::with_capacity(sigs.len() * COMPRESSIONS_PER_SIG);
    let mut roots = Vec::with_capacity(sigs.len());
    for (sig, st) in sigs.iter().zip(&steps) {
        let w = build_sig_witness::<Sha256Backend>(sig, st);
        roots.push(w.computed_root);
        instances.extend(w.instances);
    }
    let bits: Vec<[bool; TREE_HEIGHT]> = sigs.iter().map(|s| s.path_bits).collect();
    prove_sound_raw(setup, instances, &steps, &roots, &bits, true, ch)
}

/// Raw prover over pre-built instances. `check_identity=false` lets tests
/// forge inconsistent witnesses to confirm the VERIFIER catches them.
#[doc(hidden)]
pub fn prove_sound_raw<Ch: Challenger>(
    setup: &Sha256HybridSetup,
    instances: Vec<([u32; 8], [u32; 16])>,
    steps_per_sig: &[[usize; V_CHAINS]],
    roots: &[Digest],
    path_bits: &[[bool; TREE_HEIGHT]],
    check_identity: bool,
    ch: &mut Ch,
) -> SoundAggregateProof {
    let k_sigs = roots.len();
    let k_log = setup.r1cs.k_log;
    let n_log = setup.r1cs.m - k_log;

    let (z_packed, a_packed, b_packed, z_lc) =
        generate_witness_with_ab_packed_and_lincheck(&instances, n_log);
    let core = flock_prover::prover::prove_fast_core(
        &setup.r1cs,
        &setup.pcs_params,
        z_packed,
        a_packed,
        b_packed,
        z_lc,
        setup.r1cs.csc_lincheck_circuit(),
        ch,
    );

    // Region folds at tau_pos.
    let (lay_a, lay_b) = layout_pair(k_log);
    let tau_pos = ch.sample_f128_vec(lay_a.tau_pos_len());
    let fold_a = ChainFold::new(&lay_a, tau_pos.clone());
    let fold_b = ChainFold::new(&lay_b, tau_pos.clone());
    let (g_h, g_out) = fold_in_out(&lay_a, setup.r1cs.layout, &core.z_packed, &fold_a);
    let (g_lo, g_hi) = fold_in_out(&lay_b, setup.r1cs.layout, &core.z_packed, &fold_b);

    // Wiring RLC.
    let rho = ch.sample_f128();
    let iv_fold = fold_a.fold_public_phys(&cv_to_phys_bits(&SHA256_IV));
    let pad_fold = fold_a.fold_public_phys(&cv_to_phys_bits(&CHAIN_PAD));
    let root_folds: Vec<F128> =
        roots.iter().map(|r| fold_a.fold_public_phys(&cv_to_phys_bits(r))).collect();
    let eqs = wiring(steps_per_sig);
    let pb = |sig: usize, lvl: usize| path_bits[sig][lvl];
    let (w4, rhs) = build_w(&eqs, rho, n_log, iv_fold, pad_fold, &root_folds, &pb);

    // Interleave to flat tables over idx = (i << 2) | slot.
    let n = 1usize << n_log;
    let mut w_flat = vec![F128::ZERO; 4 * n];
    let mut g_flat = vec![F128::ZERO; 4 * n];
    let gs = [&g_h, &g_out, &g_lo, &g_hi];
    for i in 0..n {
        for s in 0..4 {
            w_flat[(i << N_SLOTS_LOG) | s] = w4[s][i];
            g_flat[(i << N_SLOTS_LOG) | s] = gs[s][i];
        }
    }
    if check_identity {
        let total = w_flat
            .iter()
            .zip(&g_flat)
            .map(|(a, b)| *a * *b)
            .fold(F128::ZERO, |x, y| x + y);
        assert_eq!(total, rhs, "wiring identity violated — witness/wiring mismatch");
    }

    let (wiring_proof, point) = sumcheck_prove(w_flat, g_flat, ch);

    // Extra claim into the batched open.
    let claim_pt = claim_point(&tau_pos, &point, k_log);
    let sparse_eq = flock_prover::pcs::ring_switch::build_eq_sparse(&claim_pt);
    let extra = flock_prover::pcs::PackedDirectClaim {
        point: claim_pt,
        value: wiring_proof.g_at_point,
        eq_ind: flock_prover::pcs::DirectEqInd::Sparse(sparse_eq),
    };

    let padding = setup.r1cs.padding_spec();
    let ab_x = x_outer_full(&core.ab.point);
    let c_x = x_outer_full(&core.c.point);
    let pre_ab: Option<&[F128]> = core.s_hat_v_ab.as_deref();
    let pre_c: Option<&[F128]> = Some(core.s_hat_v_c.as_slice());
    let log_n = setup.r1cs.m - flock_prover::pcs::LOG_PACKING;
    let lig_config = flock_prover::pcs::ligerito::prover_config_for(
        log_n,
        setup.pcs_params.log_batch_size,
        setup.pcs_params.profile,
    )
    .expect("ligerito prover config");
    let pcs_open = flock_prover::pcs::open_batch_mixed_ligerito_with_precomputed_s_hat_v(
        core.z_packed,
        &core.prover_data,
        &core.commitment,
        &[ab_x.as_slice(), c_x.as_slice()],
        &[pre_ab, pre_c],
        std::slice::from_ref(&extra),
        &padding,
        &lig_config,
        ch,
    );

    SoundAggregateProof {
        zerocheck: core.zc_proof,
        lincheck: core.lc_proof,
        wiring: wiring_proof,
        pcs_open,
        commitment: core.commitment,
        n_signatures: k_sigs,
    }
}

/// Verify against the public statement (roots, path_bits).
pub fn verify_sound<Ch: Challenger>(
    setup: &Sha256HybridSetup,
    proof: &SoundAggregateProof,
    msgs: &[Digest],
    roots: &[Digest],
    path_bits: &[[bool; TREE_HEIGHT]],
    ch: &mut Ch,
) -> Result<(), String> {
    let k_sigs = proof.n_signatures;
    if msgs.len() != k_sigs || roots.len() != k_sigs || path_bits.len() != k_sigs {
        return Err("statement length mismatch".into());
    }
    // Derive per-chain step counts from the PUBLIC messages — this is what
    // binds the aggregate to the messages: wrong message => wrong wiring.
    let steps: Vec<[usize; V_CHAINS]> = msgs
        .iter()
        .map(|m| crate::native::encode_message::<Sha256Backend>(m).0)
        .collect();
    let (ab, c) = flock_prover::verifier::verify_core(
        &setup.r1cs,
        &proof.zerocheck,
        &proof.lincheck,
        &proof.commitment,
        setup.r1cs.csc_lincheck_circuit(),
        ch,
    )
    .map_err(|e| format!("core: {e:?}"))?;

    let k_log = setup.r1cs.k_log;
    let n_log = setup.r1cs.m - k_log;
    let (lay_a, _) = layout_pair(k_log);
    let tau_pos = ch.sample_f128_vec(lay_a.tau_pos_len());
    let fold_a = ChainFold::new(&lay_a, tau_pos.clone());

    let rho = ch.sample_f128();
    let iv_fold = fold_a.fold_public_phys(&cv_to_phys_bits(&SHA256_IV));
    let pad_fold = fold_a.fold_public_phys(&cv_to_phys_bits(&CHAIN_PAD));
    let root_folds: Vec<F128> =
        roots.iter().map(|r| fold_a.fold_public_phys(&cv_to_phys_bits(r))).collect();
    let eqs = wiring(&steps);
    let pb = |sig: usize, lvl: usize| path_bits[sig][lvl];
    let (w4, rhs) = build_w(&eqs, rho, n_log, iv_fold, pad_fold, &root_folds, &pb);

    let (point, c_final) = sumcheck_verify(&proof.wiring, rhs, ch);

    let n = 1usize << n_log;
    let mut w_flat = vec![F128::ZERO; 4 * n];
    for i in 0..n {
        for s in 0..4 {
            w_flat[(i << N_SLOTS_LOG) | s] = w4[s][i];
        }
    }
    let w_at = mle_eval(&w_flat, &point);
    if c_final != w_at * proof.wiring.g_at_point {
        return Err("wiring sumcheck final identity failed".into());
    }

    let claim_pt = claim_point(&tau_pos, &point, k_log);
    let ab_x = x_outer_full(&ab.point);
    let c_x = x_outer_full(&c.point);
    let pd = flock_prover::pcs::PackedDirectClaimRef {
        point: &claim_pt,
        value: proof.wiring.g_at_point,
    };
    let log_n = setup.r1cs.m - flock_prover::pcs::LOG_PACKING;
    let v_config = flock_prover::pcs::ligerito::verifier_config_for(
        log_n,
        setup.pcs_params.log_batch_size,
        setup.pcs_params.profile,
    )
    .expect("ligerito verifier config");
    flock_prover::pcs::verify_opening_batch_ligerito_mixed(
        &proof.commitment,
        &[ab.value, c.value],
        &[ab.point.z_skip, c.point.z_skip],
        &[ab_x.as_slice(), c_x.as_slice()],
        std::slice::from_ref(&pd),
        &proof.pcs_open,
        &v_config,
        ch,
    )
    .map_err(|e| format!("pcs: {e:?}"))
}

/// Claim point (RowMajor): [tau_pos.., slot0, slot1, 0^high, instance..].
/// Within a block, word index = (slot << 1) | pos_word; the sumcheck bound
/// idx = (i << 2) | slot LSB-first, so its first 2 coords are the slot bits.
fn claim_point(tau_pos: &[F128], sc_point: &[F128], k_log: usize) -> Vec<F128> {
    let (slot_bits, inst_bits) = sc_point.split_at(N_SLOTS_LOG);
    let high = k_log - flock_prover::pcs::LOG_PACKING - tau_pos.len() - N_SLOTS_LOG;
    let mut pt = Vec::new();
    pt.extend_from_slice(tau_pos);
    pt.extend_from_slice(slot_bits);
    pt.extend(std::iter::repeat_n(F128::ZERO, high));
    pt.extend_from_slice(inst_bits);
    pt
}
