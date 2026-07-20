//! Linkage glue (the "wiring sumcheck") that makes the aggregate proof SOUND,
//! generic over the hash backend.
//!
//! After the base R1CS proof, each instance's 256-bit slots (H, OUT, LO, HI,
//! and for BLAKE3 a DOMAIN slot) are folded to per-instance scalars at a
//! verifier point tau_pos (flock's `ChainFold`). Every wiring constraint from
//! `witness::Wire` becomes a scalar equation:
//!
//!   Link:  G[sx][i] + G[sy][j]         = 0   (char 2: equality)
//!   Pin:   G[sx][i] + fold(constant)   = 0   (IV, CHAIN_PAD, BLAKE3 domain)
//!   Root:  G[OUT][last_i] + fold(root) = 0   (public per-signature roots)
//!
//! One scalar rho combines all equations (geometric coefficients) into a single
//! claim sum_{s,i} W[s][i]*G[s][i] = RHS; a degree-2 paired-fold sumcheck over
//! the (slot, instance) cube reduces it to one MLE evaluation of the committed
//! witness, joined to the batched Ligerito PCS opening.
//!
//! Both hashes use a slot-aligned witness layout (SHA upstream; BLAKE3 via the
//! aligned-layout fork), so the four core slots sit at bytes 0/32/64/96. BLAKE3
//! additionally pins a domain slot (counter/block_len/flags) to its constant.

use flock_prover::challenger::Challenger;
use flock_prover::field::F128;
use flock_prover::lincheck::QuirkyPoint;
use flock_prover::pcs::Commitment;
use flock_prover::r1cs_hashes::chain_common::{fold_in_out, ChainFold, ChainLayout};

use crate::backend::{Backend, Digest};
use crate::native::{Signature, CHAIN_PAD};
use crate::params::*;
use crate::witness::build_sig_witness;

const SLOT_H: usize = 0;
const SLOT_OUT: usize = 1;
const SLOT_LO: usize = 2;
const SLOT_HI: usize = 3;
const SLOT_DOMAIN: usize = 4;

/// Absorb the public statement (per-signature roots, Merkle path bits, and the
/// message-derived chain positions) into the Fiat-Shamir transcript BEFORE any
/// challenge is drawn. Without this, the verifier reads the path and roots as
/// free public inputs unbound to the transcript; binding them makes every
/// downstream challenge (commitment, wiring fold, sumcheck, PCS opening) depend
/// on the exact statement being proved. Prover and verifier call this at the
/// same point with identical data, so the transcripts stay aligned.
fn absorb_statement<Ch: Challenger>(
    ch: &mut Ch,
    roots: &[Digest],
    steps: &[[usize; V_CHAINS]],
) {
    let mut bytes = Vec::new();
    for r in roots {
        for &w in r.iter() {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
    }
    // Merkle path bits are NOT absorbed: the path is a private witness, hidden by
    // the hiding zerocheck, never sent to the verifier.
    for st in steps {
        for &s in st.iter() {
            bytes.extend_from_slice(&(s as u32).to_le_bytes());
        }
    }
    ch.observe_label(b"flock-xmss-statement-v0");
    ch.observe_bytes(&bytes);
}

fn layout(k_log: usize, in_off: usize, out_off: usize) -> ChainLayout {
    ChainLayout {
        k_log,
        k_skip: 6,
        region_log: 8,
        region_bits: 256,
        input_byte_off: in_off,
        output_byte_off: out_off,
    }
}

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
    Pin { xs: usize, xi: usize, konst: usize }, // 0=IV, 1=CHAIN_PAD, 2=DOMAIN
    Root { xi: usize, sig: usize },
}

/// Deterministic wiring for K signatures, driven by message-derived per-chain
/// step counts. `has_domain` adds a per-compression domain-slot pin (BLAKE3).
fn wiring(steps_per_sig: &[[usize; V_CHAINS]], has_domain: bool) -> Vec<Eq> {
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
            // No public path-bit routing: the Merkle chain (running hash = one of
            // the two children) is enforced privately by the hiding zerocheck.
            idx += 1;
        }
        eqs.push(Eq::Root { xi: idx - 1, sig });
    }
    if has_domain {
        for xi in 0..(steps_per_sig.len() * COMPRESSIONS_PER_SIG) {
            eqs.push(Eq::Pin { xs: SLOT_DOMAIN, xi, konst: 2 });
        }
    }
    eqs
}

#[allow(clippy::too_many_arguments)]
fn build_w(
    eqs: &[Eq],
    rho: F128,
    n_slots: usize,
    n_log: usize,
    iv_fold: F128,
    pad_fold: F128,
    domain_fold: F128,
    root_folds: &[F128],
) -> (Vec<Vec<F128>>, F128) {
    let n = 1usize << n_log;
    let mut w = vec![vec![F128::ZERO; n]; n_slots];
    let mut rhs = F128::ZERO;
    let mut coef = F128::ONE;
    for eq in eqs {
        match *eq {
            Eq::Link { xs, xi, ys, yi } => {
                w[xs][xi] += coef;
                w[ys][yi] += coef; // char 2
            }
            Eq::Pin { xs, xi, konst } => {
                w[xs][xi] += coef;
                rhs += coef
                    * match konst {
                        0 => iv_fold,
                        1 => pad_fold,
                        _ => domain_fold,
                    };
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
// Paired-fold degree-2 sumcheck (char 2)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
pub struct WiringProof {
    pub rounds: Vec<(F128, F128)>,
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
            qi += (w1 + w0) * (g1 + g0);
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
// Sound aggregation (generic over backend)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SoundAggregateProofHidden {
    pub zerocheck: flock_prover::zerocheck::ZerocheckProof,
    pub lincheck: flock_prover::lincheck::LincheckProof,
    pub wiring: WiringProof,
    /// Control-flow-hiding Merkle zerocheck (transcript-bound). Enforces the
    /// running hash is one of the two children at each level, without a path bit.
    pub hiding: crate::hiding::HidingProof,
    pub pcs_open: flock_prover::pcs::BatchOpeningProofLigerito,
    pub commitment: Commitment,
    pub n_signatures: usize,
}

/// Membership variant: prove K signatures whose XMSS pubkeys are all leaves of a
/// single committed validator-set root `V`. The per-signer Merkle path rises from
/// the signer's leaf to `V` (hidden, enforced by the hiding zerocheck), so the
/// public input is just `{V, messages}` — one root, not K. Returns `(proof, V)`.
pub fn prove_sound_membership<B: Backend, Ch: Challenger>(
    setup: &B::Setup,
    sigs: &[Signature],
    msgs: &[Digest],
    ch: &mut Ch,
) -> (SoundAggregateProofHidden, Digest) {
    assert_eq!(sigs.len(), msgs.len());
    let steps: Vec<[usize; V_CHAINS]> =
        msgs.iter().map(|m| crate::native::encode_message::<B>(m).0).collect();
    // Each signer's XMSS pubkey (leaf), then the shared validator tree over them.
    let leaves: Vec<Digest> = sigs
        .iter()
        .zip(&steps)
        .map(|(s, st)| crate::native::compute_leaf::<B>(s, st))
        .collect();
    let (v, paths) = crate::native::build_validator_set::<B>(&leaves);
    let mut instances = Vec::with_capacity(sigs.len() * COMPRESSIONS_PER_SIG);
    for (i, (sig, st)) in sigs.iter().zip(&steps).enumerate() {
        // Rebuild the signature with its membership path (leaf -> V).
        let sig_m = Signature {
            chain_values: sig.chain_values,
            auth_path: paths[i].0,
            path_bits: paths[i].1,
        };
        let w = build_sig_witness::<B>(&sig_m, st);
        debug_assert_eq!(w.computed_root, v, "membership path must reach V");
        instances.extend(w.instances);
    }
    let roots = vec![v; sigs.len()];
    let proof = prove_sound_raw_hidden::<B, Ch>(setup, instances, &steps, &roots, true, ch);
    (proof, v)
}

/// Verify the membership variant: public input is a single validator-set root
/// `V` plus the messages — the K individual signer roots are never revealed.
pub fn verify_sound_membership<B: Backend, Ch: Challenger>(
    setup: &B::Setup,
    proof: &SoundAggregateProofHidden,
    msgs: &[Digest],
    v: Digest,
    ch: &mut Ch,
) -> Result<(), String> {
    let roots = vec![v; proof.n_signatures];
    verify_sound_hidden::<B, Ch>(setup, proof, msgs, &roots, ch)
}

pub fn prove_sound_hidden<B: Backend, Ch: Challenger>(
    setup: &B::Setup,
    sigs: &[Signature],
    msgs: &[Digest],
    ch: &mut Ch,
) -> SoundAggregateProofHidden {
    assert_eq!(sigs.len(), msgs.len());
    let steps: Vec<[usize; V_CHAINS]> =
        msgs.iter().map(|m| crate::native::encode_message::<B>(m).0).collect();
    let mut instances = Vec::with_capacity(sigs.len() * COMPRESSIONS_PER_SIG);
    let mut roots = Vec::with_capacity(sigs.len());
    for (sig, st) in sigs.iter().zip(&steps) {
        let w = build_sig_witness::<B>(sig, st);
        roots.push(w.computed_root);
        instances.extend(w.instances);
    }
    prove_sound_raw_hidden::<B, Ch>(setup, instances, &steps, &roots, true, ch)
}

/// Raw prover. `check_identity=false` lets tests forge witnesses to confirm the
/// verifier rejects them.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn prove_sound_raw_hidden<B: Backend, Ch: Challenger>(
    setup: &B::Setup,
    instances: Vec<B::Instance>,
    steps_per_sig: &[[usize; V_CHAINS]],
    roots: &[Digest],
    check_identity: bool,
    ch: &mut Ch,
) -> SoundAggregateProofHidden {
    // Bind the public statement to the transcript before anything is committed.
    absorb_statement(ch, roots, steps_per_sig);

    let k_log = B::k_log(setup);
    let n_log = B::m(setup) - k_log;
    let r1cs = B::r1cs(setup);
    let pcs_params = B::pcs_params(setup);

    let (z_packed, a_packed, b_packed, z_lc) = B::gen_witness_ab(&instances, n_log);
    let core = flock_prover::prover::prove_fast_core(
        r1cs,
        pcs_params,
        z_packed,
        a_packed,
        b_packed,
        z_lc,
        r1cs.csc_lincheck_circuit(),
        ch,
    );

    let off = B::slot_byte_offsets();
    let lay_a = layout(k_log, off[0], off[1]);
    let tau_pos = ch.sample_f128_vec(lay_a.tau_pos_len());
    let fold_a = ChainFold::new(&lay_a, tau_pos.clone());

    let n_slots = 1usize << B::N_SLOTS_LOG;
    let domain = B::domain_slot();
    // The packed-direct claim opens `z_packed` over the WHOLE 2^N_SLOTS_LOG slot
    // cube. So `g_flat` must faithfully fold z_packed at EVERY region s (byte
    // s*32), not just the wiring slots — otherwise the padding slots (which hold
    // real, nonzero witness data, e.g. BLAKE3's g-function region 5) make the
    // committed MLE disagree with `g_at_point`. Padding slots keep w=0, so the
    // sumcheck claim and rhs are unchanged; only the opened value is corrected.
    let g_store: Vec<Vec<F128>> = (0..n_slots)
        .map(|s| {
            let byte = s * 32;
            let lay = layout(k_log, byte, byte);
            let fold = ChainFold::new(&lay, tau_pos.clone());
            fold_in_out(&lay, r1cs.layout, &core.z_packed, &fold).0
        })
        .collect();
    let gs: Vec<&[F128]> = g_store.iter().map(|v| v.as_slice()).collect();

    // --- Control-flow-hiding Merkle constraint (M3), transcript-bound ---
    // For every Merkle level, enforce (g_h + g_lo)(g_h + g_hi) = 0 on the real
    // folds, where g_h is the running hash (previous OUT). This proves the
    // running hash is ONE of the two children without revealing which — no path
    // bit. Batched into one product zerocheck over the Merkle-instance cube, run
    // on the MAIN transcript so its challenges are Fiat-Shamir bound.
    let n = 1usize << n_log;
    let mask = merkle_mask(steps_per_sig.len(), n);
    let t_h = crate::ztime::Instant::now();
    let (hiding_proof, hpts) = crate::hiding::prove(
        &g_store[SLOT_OUT],
        &g_store[SLOT_LO],
        &g_store[SLOT_HI],
        &mask,
        ch,
    );
    if std::env::var("CFH_PROFILE").is_ok() {
        let sz = bincode::serialize(&hiding_proof).map(|b| b.len()).unwrap_or(0);
        eprintln!(
            "[cfh] hiding (full-cube masked zerocheck + shift): 2^{} instances, prove {:.3} ms, +{} B",
            n_log,
            t_h.elapsed().as_secs_f64() * 1e3,
            sz,
        );
    }
    // Three packed-direct claims binding the hiding openings to the commitment:
    // g_lo(z), g_hi(z) at slots LO/HI over instance-point z; g_out(z2) at slot
    // OUT over z2 (the shift sumcheck's point).
    let hiding_claims = [
        hiding_claim::<B>(&tau_pos, SLOT_LO, &hpts.z, k_log, hiding_proof.g_lo_z),
        hiding_claim::<B>(&tau_pos, SLOT_HI, &hpts.z, k_log, hiding_proof.g_hi_z),
        hiding_claim::<B>(&tau_pos, SLOT_OUT, &hpts.z2, k_log, hiding_proof.g_out_z2),
    ];

    let rho = ch.sample_f128();
    let iv_fold = fold_a.fold_public_phys(&B::digest_to_phys_bits(&B::iv()));
    let pad_fold = fold_a.fold_public_phys(&B::digest_to_phys_bits(&CHAIN_PAD));
    let domain_fold = domain
        .as_ref()
        .map(|(_, _, phys)| fold_a.fold_public_phys(phys))
        .unwrap_or(F128::ZERO);
    let root_folds: Vec<F128> = roots
        .iter()
        .map(|r| fold_a.fold_public_phys(&B::digest_to_phys_bits(r)))
        .collect();

    let eqs = wiring(steps_per_sig, domain.is_some());
    let (w_slots, rhs) = build_w(
        &eqs, rho, n_slots, n_log, iv_fold, pad_fold, domain_fold, &root_folds,
    );

    let n = 1usize << n_log;
    let mut w_flat = vec![F128::ZERO; n_slots * n];
    let mut g_flat = vec![F128::ZERO; n_slots * n];
    for i in 0..n {
        for s in 0..n_slots {
            w_flat[(i << B::N_SLOTS_LOG) | s] = w_slots[s][i];
            if s < gs.len() {
                g_flat[(i << B::N_SLOTS_LOG) | s] = gs[s][i];
            }
        }
    }
    if check_identity {
        let total = w_flat
            .iter()
            .zip(&g_flat)
            .map(|(a, b)| *a * *b)
            .fold(F128::ZERO, |x, y| x + y);
        assert_eq!(total, rhs, "wiring identity violated");
    }

    let (wiring_proof, point) = sumcheck_prove(w_flat, g_flat, ch);

    let claim_pt = claim_point(&tau_pos, &point, k_log, B::N_SLOTS_LOG);
    let sparse_eq = flock_prover::pcs::ring_switch::build_eq_sparse(&claim_pt);
    let extra = flock_prover::pcs::PackedDirectClaim {
        point: claim_pt,
        value: wiring_proof.g_at_point,
        eq_ind: flock_prover::pcs::DirectEqInd::Sparse(sparse_eq),
    };

    let padding = r1cs.padding_spec();
    let ab_x = x_outer_full(&core.ab.point);
    let c_x = x_outer_full(&core.c.point);
    let pre_ab: Option<&[F128]> = core.s_hat_v_ab.as_deref();
    let pre_c: Option<&[F128]> = Some(core.s_hat_v_c.as_slice());
    let log_n = B::m(setup) - flock_prover::pcs::LOG_PACKING;
    let lig_config = flock_prover::pcs::ligerito::prover_config_for(
        log_n,
        pcs_params.log_batch_size,
        pcs_params.profile,
    )
    .expect("ligerito prover config");
    let mut all_extra = vec![extra];
    all_extra.extend(hiding_claims);
    let pcs_open = flock_prover::pcs::open_batch_mixed_ligerito_with_precomputed_s_hat_v(
        core.z_packed,
        &core.prover_data,
        &core.commitment,
        &[ab_x.as_slice(), c_x.as_slice()],
        &[pre_ab, pre_c],
        &all_extra,
        &padding,
        &lig_config,
        ch,
    );

    SoundAggregateProofHidden {
        zerocheck: core.zc_proof,
        lincheck: core.lc_proof,
        wiring: wiring_proof,
        hiding: hiding_proof,
        pcs_open,
        commitment: core.commitment,
        n_signatures: roots.len(),
    }
}

/// Public mask over the instance cube: 1 on Merkle-level instances (the last
/// `TREE_HEIGHT` compressions of each signature), 0 elsewhere.
fn merkle_mask(k_sigs: usize, n: usize) -> Vec<F128> {
    let mut m = vec![F128::ZERO; n];
    let m_lo = COMPRESSIONS_PER_SIG - TREE_HEIGHT;
    for sig in 0..k_sigs {
        let base = sig * COMPRESSIONS_PER_SIG;
        for l in 0..TREE_HEIGHT {
            m[base + m_lo + l] = F128::ONE;
        }
    }
    m
}

/// Build a packed-direct claim opening the committed witness at (slot, inst_pt):
/// the folded value of `slot` over instances evaluated at `inst_pt`.
fn hiding_claim<B: Backend>(
    tau_pos: &[F128],
    slot: usize,
    inst_pt: &[F128],
    k_log: usize,
    value: F128,
) -> flock_prover::pcs::PackedDirectClaim {
    let mut sc_point = Vec::with_capacity(B::N_SLOTS_LOG + inst_pt.len());
    for bit in 0..B::N_SLOTS_LOG {
        sc_point.push(if (slot >> bit) & 1 == 1 { F128::ONE } else { F128::ZERO });
    }
    sc_point.extend_from_slice(inst_pt);
    let claim_pt = claim_point(tau_pos, &sc_point, k_log, B::N_SLOTS_LOG);
    let sparse_eq = flock_prover::pcs::ring_switch::build_eq_sparse(&claim_pt);
    flock_prover::pcs::PackedDirectClaim {
        point: claim_pt,
        value,
        eq_ind: flock_prover::pcs::DirectEqInd::Sparse(sparse_eq),
    }
}

pub fn verify_sound_hidden<B: Backend, Ch: Challenger>(
    setup: &B::Setup,
    proof: &SoundAggregateProofHidden,
    msgs: &[Digest],
    roots: &[Digest],
    ch: &mut Ch,
) -> Result<(), String> {
    let k_sigs = proof.n_signatures;
    if msgs.len() != k_sigs || roots.len() != k_sigs {
        return Err("statement length mismatch".into());
    }
    // NOTE: the verifier never receives the Merkle path — it is a private witness
    // hidden by the hiding zerocheck. Only {roots, messages} are public inputs.
    let steps: Vec<[usize; V_CHAINS]> =
        msgs.iter().map(|m| crate::native::encode_message::<B>(m).0).collect();

    // Bind the public statement to the transcript, matching the prover.
    absorb_statement(ch, roots, &steps);

    let r1cs = B::r1cs(setup);
    let (ab, c) = flock_prover::verifier::verify_core(
        r1cs,
        &proof.zerocheck,
        &proof.lincheck,
        &proof.commitment,
        r1cs.csc_lincheck_circuit(),
        ch,
    )
    .map_err(|e| format!("core: {e:?}"))?;

    let k_log = B::k_log(setup);
    let n_log = B::m(setup) - k_log;
    let off = B::slot_byte_offsets();
    let lay_a = layout(k_log, off[0], off[1]);
    let tau_pos = ch.sample_f128_vec(lay_a.tau_pos_len());
    let fold_a = ChainFold::new(&lay_a, tau_pos.clone());
    let domain = B::domain_slot();
    let n_slots = 1usize << B::N_SLOTS_LOG;

    // Control-flow-hiding zerocheck + shift sumcheck (transcript-bound), matching
    // the prover's placement between tau_pos and rho. Replays the transcript and
    // reduces to points z, z2; the final identities are checked after the PCS
    // confirms g_lo(z)/g_hi(z)/g_out(z2).
    let hiding_red = crate::hiding::verify_reduce(&proof.hiding, n_log, ch)
        .map_err(|e| format!("hiding: {e}"))?;

    let rho = ch.sample_f128();
    let iv_fold = fold_a.fold_public_phys(&B::digest_to_phys_bits(&B::iv()));
    let pad_fold = fold_a.fold_public_phys(&B::digest_to_phys_bits(&CHAIN_PAD));
    let domain_fold = domain
        .as_ref()
        .map(|(_, _, phys)| fold_a.fold_public_phys(phys))
        .unwrap_or(F128::ZERO);
    let root_folds: Vec<F128> = roots
        .iter()
        .map(|r| fold_a.fold_public_phys(&B::digest_to_phys_bits(r)))
        .collect();

    let eqs = wiring(&steps, domain.is_some());
    let (w_slots, rhs) = build_w(
        &eqs, rho, n_slots, n_log, iv_fold, pad_fold, domain_fold, &root_folds,
    );

    let (point, c_final) = sumcheck_verify(&proof.wiring, rhs, ch);

    let n = 1usize << n_log;
    let mut w_flat = vec![F128::ZERO; n_slots * n];
    for i in 0..n {
        for s in 0..n_slots {
            w_flat[(i << B::N_SLOTS_LOG) | s] = w_slots[s][i];
        }
    }
    if c_final != mle_eval(&w_flat, &point) * proof.wiring.g_at_point {
        return Err("wiring sumcheck final identity failed".into());
    }

    let claim_pt = claim_point(&tau_pos, &point, k_log, B::N_SLOTS_LOG);
    let ab_x = x_outer_full(&ab.point);
    let c_x = x_outer_full(&c.point);
    let pd = flock_prover::pcs::PackedDirectClaimRef {
        point: &claim_pt,
        value: proof.wiring.g_at_point,
    };
    // Hiding claim points (same slot-encoded construction as the prover).
    let hclaim_pt = |slot: usize, inst_pt: &[F128]| -> Vec<F128> {
        let mut sc = Vec::with_capacity(B::N_SLOTS_LOG + inst_pt.len());
        for bit in 0..B::N_SLOTS_LOG {
            sc.push(if (slot >> bit) & 1 == 1 { F128::ONE } else { F128::ZERO });
        }
        sc.extend_from_slice(inst_pt);
        claim_point(&tau_pos, &sc, k_log, B::N_SLOTS_LOG)
    };
    let h_lo_pt = hclaim_pt(SLOT_LO, &hiding_red.z);
    let h_hi_pt = hclaim_pt(SLOT_HI, &hiding_red.z);
    let h_out_pt = hclaim_pt(SLOT_OUT, &hiding_red.z2);
    let pds = [
        pd,
        flock_prover::pcs::PackedDirectClaimRef { point: &h_lo_pt, value: proof.hiding.g_lo_z },
        flock_prover::pcs::PackedDirectClaimRef { point: &h_hi_pt, value: proof.hiding.g_hi_z },
        flock_prover::pcs::PackedDirectClaimRef { point: &h_out_pt, value: proof.hiding.g_out_z2 },
    ];
    let log_n = B::m(setup) - flock_prover::pcs::LOG_PACKING;
    let pcs_params = B::pcs_params(setup);
    let v_config = flock_prover::pcs::ligerito::verifier_config_for(
        log_n,
        pcs_params.log_batch_size,
        pcs_params.profile,
    )
    .expect("ligerito verifier config");
    flock_prover::pcs::verify_opening_batch_ligerito_mixed(
        &proof.commitment,
        &[ab.value, c.value],
        &[ab.point.z_skip, c.point.z_skip],
        &[ab_x.as_slice(), c_x.as_slice()],
        &pds,
        &proof.pcs_open,
        &v_config,
        ch,
    )
    .map_err(|e| format!("pcs: {e:?}"))?;

    // Hiding final identities — now that g_lo(z)/g_hi(z)/g_out(z2) are PCS-bound
    // to the commitment, check the two sumchecks close against them.
    let mask = merkle_mask(k_sigs, n);
    let mask_at_z = mle_eval(&mask, &hiding_red.z);
    crate::hiding::finish(
        &hiding_red,
        &proof.hiding,
        mask_at_z,
        proof.hiding.g_lo_z,
        proof.hiding.g_hi_z,
    )
    .map_err(|e| format!("{e}"))?;
    Ok(())
}

/// Claim point (RowMajor): [tau_pos.., slot_bits.., 0^high, instance..].
fn claim_point(tau_pos: &[F128], sc_point: &[F128], k_log: usize, n_slots_log: usize) -> Vec<F128> {
    let (slot_bits, inst_bits) = sc_point.split_at(n_slots_log);
    let high = k_log - flock_prover::pcs::LOG_PACKING - tau_pos.len() - n_slots_log;
    let mut pt = Vec::new();
    pt.extend_from_slice(tau_pos);
    pt.extend_from_slice(slot_bits);
    pt.extend(std::iter::repeat_n(F128::ZERO, high));
    pt.extend_from_slice(inst_bits);
    pt
}
