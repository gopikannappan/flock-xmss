//! M3 soundness characterization: is a broken Merkle chain rejected end-to-end?
use flock_xmss::backend::{Backend, Blake3Backend};
use flock_xmss::glue_hidden::{prove_sound_raw_hidden, verify_sound_hidden};
use flock_xmss::native::{encode_message, keygen, sign, Rng, Signature};
use flock_xmss::params::{COMPRESSIONS_PER_SIG, TREE_HEIGHT, V_CHAINS};
use flock_xmss::witness::build_sig_witness;
use flock_prover::challenger::FsChallenger;

#[test]
fn broken_merkle_chain_rejected() {
    let k = 4;
    let keys: Vec<_> = (0..k).map(|i| keygen::<Blake3Backend>(0xB3 + i as u64)).collect();
    let msgs: Vec<[u32; 8]> = (0..k).map(|i| Rng(0xCD00 + i as u64).digest()).collect();
    let sigs: Vec<Signature> = keys.iter().zip(&msgs).map(|(kp, m)| sign::<Blake3Backend>(kp, m)).collect();
    let roots: Vec<_> = keys.iter().map(|kp| kp.root).collect();
    let _bits: Vec<[bool; TREE_HEIGHT]> = sigs.iter().map(|s| s.path_bits).collect();
    let s = Blake3Backend::setup(k * COMPRESSIONS_PER_SIG);
    let steps: Vec<[usize; V_CHAINS]> = msgs.iter().map(|m| encode_message::<Blake3Backend>(m).0).collect();

    let mut inst = Vec::new();
    for (sig, st) in sigs.iter().zip(&steps) {
        inst.extend(build_sig_witness::<Blake3Backend>(sig, st).instances);
    }
    // Corrupt a Merkle-level compression (last TREE_HEIGHT of the 168-block):
    // sig 0's Merkle levels are indices 150..167. Break level 155's input word,
    // producing a valid compression whose output no longer chains to the parent.
    let merkle_idx = (COMPRESSIONS_PER_SIG - TREE_HEIGHT) + 5; // 155
    inst[merkle_idx].1[0] ^= 1;

    let mut chp = FsChallenger::new(b"fx-b3");
    let proof = prove_sound_raw_hidden::<Blake3Backend, _>(&s, inst, &steps, &roots, false, &mut chp);
    let mut chv = FsChallenger::new(b"fx-b3");
    let r = verify_sound_hidden::<Blake3Backend, _>(&s, &proof, &msgs, &roots, &mut chv);
    eprintln!("[forgery] broken Merkle chain -> {r:?}");
    assert!(r.is_err(), "a broken Merkle chain MUST be rejected end-to-end");
}
