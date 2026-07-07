//! Control-flow-hiding Merkle constraint (M3), fully PCS-bound.
//!
//! Per Merkle level: `(d + g_lo)(d + g_hi) = 0`, where `d` is the running hash
//! (previous compression's OUT) and g_lo/g_hi the two children. In a field this
//! forces `d ∈ {g_lo, g_hi}` without revealing which. Run over the FULL instance
//! cube with a public `mask` (1 on Merkle levels), so the reduced point `z` is a
//! full-cube point whose g_lo(z)/g_hi(z)/g_out openings are ordinary packed-
//! direct claims on the committed witness.
//!
//! Two sumchecks, both on the main transcript:
//!  1. Masked product zerocheck  Σ_i eq(r,i)·mask[i]·A[i]·B[i] = 0  (degree 4),
//!     A=d+g_lo, B=d+g_hi. Reduces to a claim at random `z` needing d(z),
//!     g_lo(z), g_hi(z).
//!  2. Shift sumcheck  d(z) = Σ_j eq(z, j+1)·g_out[j]  (binds the running hash
//!     `d` to the committed OUT slot). Reduces to a claim at random `z2` needing
//!     g_out(z2). `eq(z, ·+1)` is public, computed by the verifier.
//!
//! The caller (glue) supplies g_lo(z), g_hi(z), g_out(z2) as PCS-bound values;
//! this module checks both sumchecks' final identities against them.

use flock_prover::challenger::Challenger;
use flock_prover::field::F128;

/// eq(r, ·) table, LSB-first: index i's bit k pairs with r[k]. (Process r in
/// reverse so the doubling — which makes each new bit the LOW bit — lands r[0]
/// on the low bit, matching the LSB-first sumcheck fold order.)
fn eq_table(r: &[F128]) -> Vec<F128> {
    let mut t = vec![F128::ONE];
    for &rj in r.iter().rev() {
        let mut nt = Vec::with_capacity(t.len() * 2);
        for &e in &t {
            nt.push(e * (F128::ONE + rj));
            nt.push(e * rj);
        }
        t = nt;
    }
    t
}

/// eq(a, b) closed form over F128^v (multilinear), LSB-first pairing.
fn eq_eval(a: &[F128], b: &[F128]) -> F128 {
    a.iter()
        .zip(b)
        .fold(F128::ONE, |acc, (x, y)| acc * (*x * *y + (F128::ONE + *x) * (F128::ONE + *y)))
}

/// Lagrange-eval a univariate given its values at `0..deg+1`.
fn interp(evals: &[F128], c: F128) -> F128 {
    let m = evals.len();
    let xs: Vec<F128> = (0..m).map(|i| F128::new(i as u64, 0)).collect();
    let mut acc = F128::ZERO;
    for i in 0..m {
        let (mut num, mut den) = (F128::ONE, F128::ONE);
        for j in 0..m {
            if i != j {
                num *= c + xs[j];
                den *= xs[i] + xs[j];
            }
        }
        acc += evals[i] * num * den.inv();
    }
    acc
}

/// Fold a set of tables in lockstep at challenge `c` (LSB-first).
fn fold_all(tables: &mut [&mut Vec<F128>], c: F128) {
    for t in tables.iter_mut() {
        let half = t.len() / 2;
        for j in 0..half {
            t[j] = t[2 * j] + c * (t[2 * j + 1] + t[2 * j]);
        }
        t.truncate(half);
    }
}

#[derive(serde::Serialize, Clone)]
pub struct HidingProof {
    /// Masked product zerocheck rounds (5 evals each: degree-4 poly).
    pub zc_rounds: Vec<[F128; 5]>,
    /// Shift sumcheck rounds (3 evals each: degree-2).
    pub shift_rounds: Vec<[F128; 3]>,
    /// Running-hash evaluation d(z), bound by the shift sumcheck.
    pub d_z: F128,
    /// g_out(z2), the shift sumcheck's committed opening (also a PCS claim).
    pub g_out_z2: F128,
    /// g_lo(z), g_hi(z): the child openings at the zerocheck point (PCS claims).
    pub g_lo_z: F128,
    pub g_hi_z: F128,
}

/// Build the running-hash array d[i] = g_out[i-1] (d[0] = 0; instance 0 is never
/// a Merkle level so mask[0] = 0).
fn running_hash(g_out: &[F128]) -> Vec<F128> {
    let n = g_out.len();
    let mut d = vec![F128::ZERO; n];
    for i in 1..n {
        d[i] = g_out[i - 1];
    }
    d
}

pub fn prove<Ch: Challenger>(
    g_out: &[F128],
    g_lo: &[F128],
    g_hi: &[F128],
    mask: &[F128],
    ch: &mut Ch,
) -> (HidingProof, PublicPoints) {
    let n = g_out.len();
    let v = n.trailing_zeros() as usize;
    assert_eq!(1 << v, n);
    let d = running_hash(g_out);

    // ---- 1. Masked product zerocheck: Σ eq(r,i)·mask·A·B = 0 ----
    let r = ch.sample_f128_vec(v);
    let mut eq = eq_table(&r);
    let mut msk = mask.to_vec();
    let mut a: Vec<F128> = (0..n).map(|i| d[i] + g_lo[i]).collect();
    let mut b: Vec<F128> = (0..n).map(|i| d[i] + g_hi[i]).collect();
    let mut zc_rounds = Vec::with_capacity(v);
    let mut z = Vec::with_capacity(v);
    let mut len = n;
    for _ in 0..v {
        let half = len / 2;
        let mut evals = [F128::ZERO; 5];
        for j in 0..half {
            let (e0, e1) = (eq[2 * j], eq[2 * j + 1]);
            let (m0, m1) = (msk[2 * j], msk[2 * j + 1]);
            let (a0, a1) = (a[2 * j], a[2 * j + 1]);
            let (b0, b1) = (b[2 * j], b[2 * j + 1]);
            for (k, t) in (0..5).map(|k| (k, F128::new(k as u64, 0))) {
                evals[k] += (e0 + t * (e1 + e0))
                    * (m0 + t * (m1 + m0))
                    * (a0 + t * (a1 + a0))
                    * (b0 + t * (b1 + b0));
            }
        }
        for e in &evals {
            ch.observe_f128(*e);
        }
        let c = ch.sample_f128();
        fold_all(&mut [&mut eq, &mut msk, &mut a, &mut b], c);
        len = half;
        zc_rounds.push(evals);
        z.push(c);
    }
    let d_z = {
        // d(z) recomputed from the committed OUT via its MLE (prover side).
        let mut dt = d.clone();
        for &c in &z {
            let half = dt.len() / 2;
            for j in 0..half {
                dt[j] = dt[2 * j] + c * (dt[2 * j + 1] + dt[2 * j]);
            }
            dt.truncate(half);
        }
        dt[0]
    };

    // ---- 2. Shift sumcheck: d(z) = Σ_j eq(z, j+1)·g_out[j] ----
    // seq[j] = eq(z, j+1). Prove Σ_j seq[j]·g_out[j] = d_z.
    let mut seq = vec![F128::ZERO; n];
    {
        let eqz = eq_table(&z); // eqz[y] = eq(z, y)
        for j in 0..n - 1 {
            seq[j] = eqz[j + 1];
        }
    }
    let mut sg = g_out.to_vec();
    let mut ss = seq.clone();
    let mut shift_rounds = Vec::with_capacity(v);
    let mut z2 = Vec::with_capacity(v);
    let mut len = n;
    for _ in 0..v {
        let half = len / 2;
        let mut evals = [F128::ZERO; 3];
        for j in 0..half {
            let (s0, s1) = (ss[2 * j], ss[2 * j + 1]);
            let (g0, g1) = (sg[2 * j], sg[2 * j + 1]);
            for (k, t) in (0..3).map(|k| (k, F128::new(k as u64, 0))) {
                evals[k] += (s0 + t * (s1 + s0)) * (g0 + t * (g1 + g0));
            }
        }
        for e in &evals {
            ch.observe_f128(*e);
        }
        let c = ch.sample_f128();
        fold_all(&mut [&mut ss, &mut sg], c);
        len = half;
        shift_rounds.push(evals);
        z2.push(c);
    }
    let g_out_z2 = sg[0];

    let fold_at = |arr: &[F128], pt: &[F128]| -> F128 {
        let mut t = arr.to_vec();
        for &c in pt {
            let half = t.len() / 2;
            for j in 0..half {
                t[j] = t[2 * j] + c * (t[2 * j + 1] + t[2 * j]);
            }
            t.truncate(half);
        }
        t[0]
    };
    let g_lo_z = fold_at(g_lo, &z);
    let g_hi_z = fold_at(g_hi, &z);

    (
        HidingProof { zc_rounds, shift_rounds, d_z, g_out_z2, g_lo_z, g_hi_z },
        PublicPoints { z, z2 },
    )
}

/// The sumcheck points the verifier re-derives; glue uses them to build the
/// g_lo(z)/g_hi(z)/g_out(z2) packed-direct claims.
pub struct PublicPoints {
    pub z: Vec<F128>,
    pub z2: Vec<F128>,
}

/// Reduced verifier state after replaying both sumchecks' transcripts. The
/// final identities are deferred until glue supplies the PCS-bound openings.
pub struct Reduced {
    pub r: Vec<F128>,
    pub z: Vec<F128>,
    pub z2: Vec<F128>,
    pub zc_claim: F128,
    pub shift_claim: F128,
}

/// Replay both sumchecks on the transcript (matching the prover's ordering:
/// sample r, zerocheck rounds, shift rounds), checking round consistency.
pub fn verify_reduce<Ch: Challenger>(
    proof: &HidingProof,
    v: usize,
    ch: &mut Ch,
) -> Result<Reduced, String> {
    if proof.zc_rounds.len() != v || proof.shift_rounds.len() != v {
        return Err("hiding: wrong round count".into());
    }
    let r = ch.sample_f128_vec(v); // matches prove's r
    let mut claim = F128::ZERO;
    let mut z = Vec::with_capacity(v);
    for evals in &proof.zc_rounds {
        if evals[0] + evals[1] != claim {
            return Err("hiding: constraint not satisfied (running hash not a child)".into());
        }
        for e in evals {
            ch.observe_f128(*e);
        }
        let c = ch.sample_f128();
        claim = interp(evals, c);
        z.push(c);
    }
    let zc_claim = claim;

    let mut sclaim = proof.d_z; // shift sumcheck initial claim = d(z)
    let mut z2 = Vec::with_capacity(v);
    for evals in &proof.shift_rounds {
        if evals[0] + evals[1] != sclaim {
            return Err("hiding: shift sumcheck inconsistent".into());
        }
        for e in evals {
            ch.observe_f128(*e);
        }
        let c = ch.sample_f128();
        sclaim = interp(evals, c);
        z2.push(c);
    }
    Ok(Reduced { r, z, z2, zc_claim, shift_claim: sclaim })
}

/// Final identities, checked after glue confirms the PCS openings
/// g_lo(z), g_hi(z), g_out(z2).
pub fn finish(
    red: &Reduced,
    proof: &HidingProof,
    mask_at_z: F128,
    g_lo_z: F128,
    g_hi_z: F128,
) -> Result<(), String> {
    let a_z = proof.d_z + g_lo_z;
    let b_z = proof.d_z + g_hi_z;
    let eq_rz = eq_eval(&red.r, &red.z);
    if red.zc_claim != eq_rz * mask_at_z * a_z * b_z {
        return Err("hiding: zerocheck final identity failed".into());
    }
    let seq_z2 = shifted_eq_eval(&red.z, &red.z2);
    if red.shift_claim != seq_z2 * proof.g_out_z2 {
        return Err("hiding: shift final identity failed".into());
    }
    Ok(())
}

/// Evaluate the MLE of `seq[j] = eq(z, j+1)` at point `z2`. seq is the eq(z,·)
/// table shifted down by one index; its MLE at z2 has a closed form via the
/// binary "+1" carry, so we build the small table and fold. n = 2^v.
fn shifted_eq_eval(z: &[F128], z2: &[F128]) -> F128 {
    let v = z.len();
    let n = 1usize << v;
    let eqz = eq_table(z);
    let mut seq = vec![F128::ZERO; n];
    for j in 0..n - 1 {
        seq[j] = eqz[j + 1];
    }
    // fold seq at z2
    for &c in z2 {
        let half = seq.len() / 2;
        for j in 0..half {
            seq[j] = seq[2 * j] + c * (seq[2 * j + 1] + seq[2 * j]);
        }
        seq.truncate(half);
    }
    seq[0]
}
