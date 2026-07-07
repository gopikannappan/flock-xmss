//! End-to-end membership: K signatures whose pubkeys are leaves of one committed
//! validator root V. Public input is {V, messages} — not K roots. A non-member
//! signature (pubkey not in V) is rejected.
use flock_xmss::backend::{Backend, Blake3Backend};
use flock_xmss::glue_hidden::{prove_sound_membership, verify_sound_membership};
use flock_xmss::native::{keygen, sign, Rng};
use flock_xmss::params::COMPRESSIONS_PER_SIG;
use flock_prover::challenger::FsChallenger;

#[test]
fn honest_membership_verifies_against_single_v() {
    let k = 4;
    let keys: Vec<_> = (0..k).map(|i| keygen::<Blake3Backend>(0xB3 + i as u64)).collect();
    let msgs: Vec<[u32; 8]> = (0..k).map(|i| Rng(0xCD00 + i as u64).digest()).collect();
    let sigs: Vec<_> = keys.iter().zip(&msgs).map(|(kp, m)| sign::<Blake3Backend>(kp, m)).collect();
    let s = Blake3Backend::setup(k * COMPRESSIONS_PER_SIG);

    let mut chp = FsChallenger::new(b"mem");
    let (proof, v) = prove_sound_membership::<Blake3Backend, _>(&s, &sigs, &msgs, &mut chp);
    let mut chv = FsChallenger::new(b"mem");
    verify_sound_membership::<Blake3Backend, _>(&s, &proof, &msgs, v, &mut chv)
        .expect("honest membership must verify against V");
}

#[test]
fn non_member_rejected() {
    // Prove membership for k signers -> V. Then verify the SAME proof against a
    // different V' (as if claiming membership in another validator set): reject.
    let k = 4;
    let keys: Vec<_> = (0..k).map(|i| keygen::<Blake3Backend>(0xB3 + i as u64)).collect();
    let msgs: Vec<[u32; 8]> = (0..k).map(|i| Rng(0xCD00 + i as u64).digest()).collect();
    let sigs: Vec<_> = keys.iter().zip(&msgs).map(|(kp, m)| sign::<Blake3Backend>(kp, m)).collect();
    let s = Blake3Backend::setup(k * COMPRESSIONS_PER_SIG);
    let mut chp = FsChallenger::new(b"mem");
    let (proof, v) = prove_sound_membership::<Blake3Backend, _>(&s, &sigs, &msgs, &mut chp);

    let mut wrong_v = v;
    wrong_v[0] ^= 1; // a different validator-set root
    let mut chv = FsChallenger::new(b"mem");
    let r = verify_sound_membership::<Blake3Backend, _>(&s, &proof, &msgs, wrong_v, &mut chv);
    assert!(r.is_err(), "membership against the wrong V MUST be rejected, got {r:?}");
}
