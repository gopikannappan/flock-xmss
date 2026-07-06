//! Multi-signature aggregation (v0), generic over the hash backend.
//!
//! v0 proves the batch R1CS over EVERY compression of K signature
//! verifications in one Flock proof. Instance-to-instance linkage is spec'd in
//! `witness::Wire` and enforced by the glue milestone (in progress); v0
//! throughput is cost-faithful (glue adds single-digit percent).

use flock_prover::challenger::FsChallenger;

use crate::backend::{Backend, Digest};
use crate::native::Signature;
use crate::params::COMPRESSIONS_PER_SIG;
use crate::witness::build_sig_witness;

pub struct AggregateProof {
    pub proof: flock_prover::proof::R1csProofLigerito,
    pub commitment: flock_prover::pcs::Commitment,
    pub n_signatures: usize,
    /// Per-signature roots computed by the witness (public inputs).
    pub roots: Vec<Digest>,
}

pub struct Aggregator<B: Backend> {
    setup: B::Setup,
    n_signatures: usize,
}

impl<B: Backend> Aggregator<B> {
    pub fn new(n_signatures: usize) -> Self {
        Self {
            setup: B::setup(n_signatures * COMPRESSIONS_PER_SIG),
            n_signatures,
        }
    }

    pub fn prove(&self, sigs: &[Signature]) -> AggregateProof {
        assert_eq!(sigs.len(), self.n_signatures);
        let mut instances: Vec<B::Instance> =
            Vec::with_capacity(self.n_signatures * COMPRESSIONS_PER_SIG);
        let mut roots = Vec::with_capacity(self.n_signatures);
        for sig in sigs {
            let w = build_sig_witness::<B>(sig);
            roots.push(w.computed_root);
            instances.extend(w.instances);
        }
        let mut ch = FsChallenger::new(b"flock-xmss-agg-v0");
        let (proof, commitment, _claim) = B::prove(&self.setup, &instances, &mut ch);
        AggregateProof { proof, commitment, n_signatures: self.n_signatures, roots }
    }

    pub fn verify(&self, agg: &AggregateProof, expected_roots: &[Digest]) -> bool {
        if agg.n_signatures != self.n_signatures || agg.roots != expected_roots {
            return false;
        }
        let mut ch = FsChallenger::new(b"flock-xmss-agg-v0");
        B::verify(&self.setup, &agg.commitment, &agg.proof, &mut ch)
    }
}
