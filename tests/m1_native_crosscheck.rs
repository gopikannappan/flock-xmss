//! Milestone-1 gate, both backends: sign/verify with MESSAGE-DERIVED chain
//! positions; witness mapping value-faithful to the native verifier.

use flock_xmss::backend::{Backend, Blake3Backend, Sha256Backend};
use flock_xmss::native::{encode_message, keygen, sign, verify, Rng};
use flock_xmss::params::{COMPRESSIONS_PER_SIG, TARGET_SUM, V_CHAINS};
use flock_xmss::witness::{build_sig_witness, replay_and_check};

fn roundtrip<B: Backend>() {
    let kp = keygen::<B>(0xC0FFEE);
    let msg = Rng(0x1234).digest();
    let sig = sign::<B>(&kp, &msg);
    assert!(verify::<B>(&sig, &msg, &kp.root), "{} honest verify", B::NAME);

    // Wrong message must fail (positions change).
    let other = Rng(0x9999).digest();
    assert!(!verify::<B>(&sig, &other, &kp.root), "{} wrong msg must fail", B::NAME);

    // Tampered signature must fail.
    let mut bad = sign::<B>(&kp, &msg);
    bad.chain_values[7][0] ^= 1;
    assert!(!verify::<B>(&bad, &msg, &kp.root), "{} tampered must fail", B::NAME);

    let (steps, _) = encode_message::<B>(&msg);
    assert_eq!(steps.iter().sum::<usize>(), TARGET_SUM);
    let w = build_sig_witness::<B>(&sig, &steps);
    assert_eq!(w.instances.len(), COMPRESSIONS_PER_SIG);
    assert_eq!(w.computed_root, kp.root, "{} witness root", B::NAME);
    assert_eq!(replay_and_check::<B>(&w), kp.root, "{} replay root", B::NAME);
}

#[test]
fn sha256_roundtrip() { roundtrip::<Sha256Backend>(); }
#[test]
fn blake3_roundtrip() { roundtrip::<Blake3Backend>(); }

#[test]
fn encoding_is_deterministic_and_message_sensitive() {
    let m1 = Rng(1).digest();
    let m2 = Rng(2).digest();
    let (a, _) = encode_message::<Sha256Backend>(&m1);
    let (b, _) = encode_message::<Sha256Backend>(&m1);
    let (c, _) = encode_message::<Sha256Backend>(&m2);
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert!(a.iter().all(|&s| s < 4) && a.len() == V_CHAINS);
}
