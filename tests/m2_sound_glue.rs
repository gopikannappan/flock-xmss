//! Soundness gate: honest proofs verify; forged wiring, wrong roots, and
//! WRONG MESSAGES are all rejected.

use flock_prover::challenger::FsChallenger;
use flock_prover::r1cs_hashes::sha2::Sha256HybridSetup;
use flock_xmss::backend::Sha256Backend;
use flock_xmss::glue::{prove_sound, prove_sound_raw, verify_sound};
use flock_xmss::native::{encode_message, keygen, sign, Rng, Signature};
use flock_xmss::params::{COMPRESSIONS_PER_SIG, TREE_HEIGHT, V_CHAINS};
use flock_xmss::witness::build_sig_witness;

type Fixtures = (Vec<Signature>, Vec<[u32; 8]>, Vec<[u32; 8]>, Vec<[bool; TREE_HEIGHT]>);

fn fixtures(k: usize) -> Fixtures {
    let keys: Vec<_> = (0..k).map(|i| keygen::<Sha256Backend>(0x600D + i as u64)).collect();
    let msgs: Vec<[u32; 8]> = (0..k).map(|i| Rng(0xAB00 + i as u64).digest()).collect();
    let sigs: Vec<_> = keys.iter().zip(&msgs).map(|(kp, m)| sign::<Sha256Backend>(kp, m)).collect();
    let roots: Vec<_> = keys.iter().map(|kp| kp.root).collect();
    let bits: Vec<_> = sigs.iter().map(|s| s.path_bits).collect();
    (sigs, msgs, roots, bits)
}

#[test]
fn honest_sound_proof_verifies() {
    let k = 4;
    let (sigs, msgs, roots, bits) = fixtures(k);
    let setup = Sha256HybridSetup::new(k * COMPRESSIONS_PER_SIG);
    let mut chp = FsChallenger::new(b"flock-xmss-sound");
    let proof = prove_sound::<Sha256Backend, _>(&setup, &sigs, &msgs, &mut chp);
    let mut chv = FsChallenger::new(b"flock-xmss-sound");
    verify_sound::<Sha256Backend, _>(&setup, &proof, &msgs, &roots, &bits, &mut chv).expect("honest must verify");
}

#[test]
fn wrong_message_rejected() {
    // THE message-binding test: same signatures, one message swapped.
    let k = 4;
    let (sigs, msgs, roots, bits) = fixtures(k);
    let setup = Sha256HybridSetup::new(k * COMPRESSIONS_PER_SIG);
    let mut chp = FsChallenger::new(b"flock-xmss-sound");
    let proof = prove_sound::<Sha256Backend, _>(&setup, &sigs, &msgs, &mut chp);
    let mut wrong = msgs.clone();
    wrong[1] = Rng(0xEEEE).digest();
    let mut chv = FsChallenger::new(b"flock-xmss-sound");
    assert!(
        verify_sound::<Sha256Backend, _>(&setup, &proof, &wrong, &roots, &bits, &mut chv).is_err(),
        "aggregate MUST be bound to the messages"
    );
}

#[test]
fn wrong_root_rejected() {
    let k = 4;
    let (sigs, msgs, mut roots, bits) = fixtures(k);
    let setup = Sha256HybridSetup::new(k * COMPRESSIONS_PER_SIG);
    let mut chp = FsChallenger::new(b"flock-xmss-sound");
    let proof = prove_sound::<Sha256Backend, _>(&setup, &sigs, &msgs, &mut chp);
    roots[2][0] ^= 1;
    let mut chv = FsChallenger::new(b"flock-xmss-sound");
    assert!(verify_sound::<Sha256Backend, _>(&setup, &proof, &msgs, &roots, &bits, &mut chv).is_err());
}

#[test]
fn forged_chain_link_rejected() {
    let k = 4;
    let (sigs, msgs, roots, bits) = fixtures(k);
    let setup = Sha256HybridSetup::new(k * COMPRESSIONS_PER_SIG);
    let steps: Vec<[usize; V_CHAINS]> =
        msgs.iter().map(|m| encode_message::<Sha256Backend>(m).0).collect();
    let mut instances = Vec::new();
    for (sig, st) in sigs.iter().zip(&steps) {
        instances.extend(build_sig_witness::<Sha256Backend>(sig, st).instances);
    }
    instances[5].1[0] ^= 1;
    let mut chp = FsChallenger::new(b"flock-xmss-sound");
    let proof = prove_sound_raw::<Sha256Backend, _>(&setup, instances, &steps, &roots, &bits, false, &mut chp);
    let mut chv = FsChallenger::new(b"flock-xmss-sound");
    assert!(verify_sound::<Sha256Backend, _>(&setup, &proof, &msgs, &roots, &bits, &mut chv).is_err());
}
