//! BLAKE3 soundness gate (aligned-layout fork): honest proofs verify; wrong
//! message, wrong root, forged chain link, and FORGED DOMAIN (flags) rejected.

use flock_prover::challenger::FsChallenger;
use flock_xmss::backend::{Backend, Blake3Backend};
use flock_xmss::glue::{prove_sound, prove_sound_raw, verify_sound};
use flock_xmss::native::{encode_message, keygen, sign, Rng, Signature};
use flock_xmss::params::{COMPRESSIONS_PER_SIG, TREE_HEIGHT, V_CHAINS};
use flock_xmss::witness::build_sig_witness;

type Fx = (Vec<Signature>, Vec<[u32; 8]>, Vec<[u32; 8]>, Vec<[bool; TREE_HEIGHT]>);
fn fixtures(k: usize) -> Fx {
    let keys: Vec<_> = (0..k).map(|i| keygen::<Blake3Backend>(0xB3 + i as u64)).collect();
    let msgs: Vec<[u32; 8]> = (0..k).map(|i| Rng(0xCD00 + i as u64).digest()).collect();
    let sigs: Vec<_> = keys.iter().zip(&msgs).map(|(kp, m)| sign::<Blake3Backend>(kp, m)).collect();
    let roots: Vec<_> = keys.iter().map(|kp| kp.root).collect();
    let bits: Vec<_> = sigs.iter().map(|s| s.path_bits).collect();
    (sigs, msgs, roots, bits)
}
fn setup(k: usize) -> <Blake3Backend as Backend>::Setup {
    Blake3Backend::setup(k * COMPRESSIONS_PER_SIG)
}

#[test]
fn honest_blake3_proof_verifies() {
    let k = 4;
    let (sigs, msgs, roots, bits) = fixtures(k);
    let s = setup(k);
    let mut chp = FsChallenger::new(b"fx-b3");
    let proof = prove_sound::<Blake3Backend, _>(&s, &sigs, &msgs, &mut chp);
    let mut chv = FsChallenger::new(b"fx-b3");
    verify_sound::<Blake3Backend, _>(&s, &proof, &msgs, &roots, &bits, &mut chv).expect("honest verify");
}

#[test]
fn blake3_wrong_message_rejected() {
    let k = 4;
    let (sigs, msgs, roots, bits) = fixtures(k);
    let s = setup(k);
    let mut chp = FsChallenger::new(b"fx-b3");
    let proof = prove_sound::<Blake3Backend, _>(&s, &sigs, &msgs, &mut chp);
    let mut wrong = msgs.clone();
    wrong[1] = Rng(0xFFFF).digest();
    let mut chv = FsChallenger::new(b"fx-b3");
    assert!(verify_sound::<Blake3Backend, _>(&s, &proof, &wrong, &roots, &bits, &mut chv).is_err());
}

#[test]
fn blake3_forged_chain_link_rejected() {
    let k = 4;
    let (sigs, msgs, roots, bits) = fixtures(k);
    let s = setup(k);
    let steps: Vec<[usize; V_CHAINS]> = msgs.iter().map(|m| encode_message::<Blake3Backend>(m).0).collect();
    let mut inst = Vec::new();
    for (sig, st) in sigs.iter().zip(&steps) {
        inst.extend(build_sig_witness::<Blake3Backend>(sig, st).instances);
    }
    inst[5].1[0] ^= 1; // corrupt a chain step input word
    let mut chp = FsChallenger::new(b"fx-b3");
    let proof = prove_sound_raw::<Blake3Backend, _>(&s, inst, &steps, &roots, &bits, false, &mut chp);
    let mut chv = FsChallenger::new(b"fx-b3");
    assert!(verify_sound::<Blake3Backend, _>(&s, &proof, &msgs, &roots, &bits, &mut chv).is_err());
}

#[test]
fn blake3_forged_domain_rejected() {
    // THE domain-pin test: flip a flag bit in one compression's domain. The
    // R1CS still holds (it just computes a different-domain BLAKE3), but the
    // domain pin must reject it.
    let k = 4;
    let (sigs, msgs, roots, bits) = fixtures(k);
    let s = setup(k);
    let steps: Vec<[usize; V_CHAINS]> = msgs.iter().map(|m| encode_message::<Blake3Backend>(m).0).collect();
    let mut inst = Vec::new();
    for (sig, st) in sigs.iter().zip(&steps) {
        inst.extend(build_sig_witness::<Blake3Backend>(sig, st).instances);
    }
    inst[3].4 ^= 0b100; // flip a flags bit (the 5th tuple field)
    let mut chp = FsChallenger::new(b"fx-b3");
    let proof = prove_sound_raw::<Blake3Backend, _>(&s, inst, &steps, &roots, &bits, false, &mut chp);
    let mut chv = FsChallenger::new(b"fx-b3");
    assert!(
        verify_sound::<Blake3Backend, _>(&s, &proof, &msgs, &roots, &bits, &mut chv).is_err(),
        "forged BLAKE3 domain MUST be rejected by the domain pin"
    );
}
