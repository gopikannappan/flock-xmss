//! M3: the transcript-bound hiding zerocheck is actually enforced by the verifier.
use flock_xmss::backend::{Backend, Blake3Backend};
use flock_xmss::glue_hidden::{prove_sound_hidden, verify_sound_hidden};
use flock_xmss::native::{keygen, sign, Rng};
use flock_xmss::params::{COMPRESSIONS_PER_SIG, TREE_HEIGHT};
use flock_prover::challenger::FsChallenger;
use flock_prover::field::F128;

#[test]
fn tampered_hiding_proof_rejected() {
    let k = 4;
    let keys: Vec<_> = (0..k).map(|i| keygen::<Blake3Backend>(0xB3 + i as u64)).collect();
    let msgs: Vec<[u32; 8]> = (0..k).map(|i| Rng(0xCD00 + i as u64).digest()).collect();
    let sigs: Vec<_> = keys.iter().zip(&msgs).map(|(kp, m)| sign::<Blake3Backend>(kp, m)).collect();
    let roots: Vec<_> = keys.iter().map(|kp| kp.root).collect();
    let _bits: Vec<[bool; TREE_HEIGHT]> = sigs.iter().map(|s| s.path_bits).collect();
    let s = Blake3Backend::setup(k * COMPRESSIONS_PER_SIG);

    let mut chp = FsChallenger::new(b"fx-b3");
    let mut proof = prove_sound_hidden::<Blake3Backend, _>(&s, &sigs, &msgs, &mut chp);

    // Corrupt a hiding opening value; breaks PCS binding + sumcheck identity.
    proof.hiding.g_lo_z += F128::ONE;
    let mut chv = FsChallenger::new(b"fx-b3");
    let r = verify_sound_hidden::<Blake3Backend, _>(&s, &proof, &msgs, &roots, &mut chv);
    // Rejected either by the PCS binding (the opening no longer matches the
    // commitment) or the hiding final identity — both are correct.
    assert!(r.is_err(), "tampered hiding opening MUST be rejected, got {r:?}");
    let msg = format!("{r:?}");
    assert!(msg.contains("pcs") || msg.contains("hiding"), "unexpected error: {msg}");
}
