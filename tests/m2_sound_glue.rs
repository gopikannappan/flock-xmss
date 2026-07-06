//! Milestone-2 gate: the wiring glue makes the proof SOUND.
//! Honest proofs verify; forged wiring (which v0 would accept) is rejected.

use flock_prover::challenger::FsChallenger;
use flock_prover::r1cs_hashes::sha2::Sha256HybridSetup;
use flock_xmss::backend::Sha256Backend;
use flock_xmss::glue::{prove_sound, prove_sound_raw, verify_sound};
use flock_xmss::native::{keygen, Signature};
use flock_xmss::params::{COMPRESSIONS_PER_SIG, TREE_HEIGHT};
use flock_xmss::witness::build_sig_witness;

fn fixtures(k: usize) -> (Vec<Signature>, Vec<[u32; 8]>, Vec<[bool; TREE_HEIGHT]>) {
    let keys: Vec<_> = (0..k).map(|i| keygen::<Sha256Backend>(0x600D + i as u64)).collect();
    let sigs: Vec<_> = keys
        .iter()
        .map(|kp| Signature {
            chain_values: kp.sig_template.chain_values,
            auth_path: kp.sig_template.auth_path,
            path_bits: kp.sig_template.path_bits,
        })
        .collect();
    let roots: Vec<_> = keys.iter().map(|kp| kp.root).collect();
    let bits: Vec<_> = sigs.iter().map(|s| s.path_bits).collect();
    (sigs, roots, bits)
}

#[test]
fn honest_sound_proof_verifies() {
    let k = 4;
    let (sigs, roots, bits) = fixtures(k);
    let setup = Sha256HybridSetup::new(k * COMPRESSIONS_PER_SIG);
    let mut chp = FsChallenger::new(b"flock-xmss-sound");
    let proof = prove_sound(&setup, &sigs, &mut chp);
    let mut chv = FsChallenger::new(b"flock-xmss-sound");
    verify_sound(&setup, &proof, &roots, &bits, &mut chv).expect("honest proof must verify");
}

#[test]
fn wrong_root_rejected() {
    let k = 4;
    let (sigs, mut roots, bits) = fixtures(k);
    let setup = Sha256HybridSetup::new(k * COMPRESSIONS_PER_SIG);
    let mut chp = FsChallenger::new(b"flock-xmss-sound");
    let proof = prove_sound(&setup, &sigs, &mut chp);
    roots[2][0] ^= 1;
    let mut chv = FsChallenger::new(b"flock-xmss-sound");
    assert!(verify_sound(&setup, &proof, &roots, &bits, &mut chv).is_err());
}

#[test]
fn forged_chain_link_rejected() {
    // Break one chain link: instance 5's input no longer equals instance 4's
    // output, but every compression stays internally valid. v0 accepts this;
    // the wiring glue must reject it.
    let k = 4;
    let (sigs, roots, bits) = fixtures(k);
    let setup = Sha256HybridSetup::new(k * COMPRESSIONS_PER_SIG);
    let mut instances = Vec::new();
    for sig in &sigs {
        instances.extend(build_sig_witness::<Sha256Backend>(sig).instances);
    }
    instances[5].1[0] ^= 1; // corrupt lo half of a mid-chain step's input
    let mut chp = FsChallenger::new(b"flock-xmss-sound");
    let proof = prove_sound_raw(&setup, instances, &roots, &bits, false, &mut chp);
    let mut chv = FsChallenger::new(b"flock-xmss-sound");
    assert!(
        verify_sound(&setup, &proof, &roots, &bits, &mut chv).is_err(),
        "forged chain link MUST be rejected by the glue"
    );
}

#[test]
fn forged_pad_rejected() {
    // Swap the pinned CHAIN_PAD for different bytes in one chain step.
    let k = 4;
    let (sigs, roots, bits) = fixtures(k);
    let setup = Sha256HybridSetup::new(k * COMPRESSIONS_PER_SIG);
    let mut instances = Vec::new();
    for sig in &sigs {
        instances.extend(build_sig_witness::<Sha256Backend>(sig).instances);
    }
    instances[7].1[12] ^= 0xdead_beef; // corrupt hi half (the pad)
    let mut chp = FsChallenger::new(b"flock-xmss-sound");
    let proof = prove_sound_raw(&setup, instances, &roots, &bits, false, &mut chp);
    let mut chv = FsChallenger::new(b"flock-xmss-sound");
    assert!(verify_sound(&setup, &proof, &roots, &bits, &mut chv).is_err());
}
