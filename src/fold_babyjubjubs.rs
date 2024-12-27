#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Projective as G1};
    use ark_grumpkin::Projective as G2;
    use std::time::Instant;

    use arkeddsa::ed_on_bn254_twist::{constraints::EdwardsVar, EdwardsProjective};

    use folding_schemes::{
        commitment::pedersen::Pedersen,
        folding::nova::{Nova, PreprocessorParam},
        frontend::FCircuit,
        transcript::poseidon::poseidon_canonical_config,
        FoldingScheme,
    };

    use crate::fcircuit::{tests::gen_signatures, FoldSigsStepCircuit};

    #[test]
    fn test_full_flow() {
        // 5 recursive steps, 10 signature verifications per step
        full_flow::<5, 10>();
        // 5 recursive steps, 50 signature verifications per step
        full_flow::<5, 50>();
    }

    fn full_flow<const N_STEPS: usize, const SIGS_PER_STEP: usize>() {
        println!("\nrunning Nova folding scheme on FoldSigsStepCircuit, with N_STEPS={}, SIGS_PER_STEP={}. Total sigs = {}", N_STEPS, SIGS_PER_STEP, N_STEPS* SIGS_PER_STEP);

        let mut rng = rand::rngs::OsRng;
        let poseidon_config = poseidon_canonical_config::<Fr>();

        let pks_sigs =
            gen_signatures::<rand::rngs::OsRng, SIGS_PER_STEP>(&mut rng, &poseidon_config, N_STEPS);

        // set the initial state
        let z_0: Vec<Fr> = vec![0_u8; 1]
            .iter()
            .map(|v| Fr::from(*v))
            .collect::<Vec<Fr>>();

        type FC<const S: usize> = FoldSigsStepCircuit<Fr, EdwardsProjective, EdwardsVar, S>;
        let f_circuit = FC::<SIGS_PER_STEP>::new(poseidon_config.clone()).unwrap();

        // define type aliases for the FoldingScheme (FS) and Decider (D), to avoid writting the
        // whole type each time
        pub type FS<const S: usize> = Nova<G1, G2, FC<S>, Pedersen<G1>, Pedersen<G2>, false>;

        // prepare the Nova prover & verifier params
        let nova_preprocess_params =
            PreprocessorParam::new(poseidon_config.clone(), f_circuit.clone());
        let start = Instant::now();
        let nova_params =
            FS::<SIGS_PER_STEP>::preprocess(&mut rng, &nova_preprocess_params).unwrap();
        println!("Nova params generated: {:?}", start.elapsed());

        // initialize the folding scheme engine, in our case we use Nova
        let mut nova = FS::<SIGS_PER_STEP>::init(&nova_params, f_circuit, z_0.clone()).unwrap();

        // run n steps of the folding iteration
        let start_full = Instant::now();
        for i in 0..N_STEPS {
            let start = Instant::now();
            nova.prove_step(rng, pks_sigs[i].clone(), None).unwrap();
            println!("Nova::prove_step {}: {:?}", nova.i, start.elapsed());
        }
        let t = start_full.elapsed();
        println!("Nova's all {} steps time: {:?}", N_STEPS, t);
        println!(
            "N_STEPS={}, SIGS_PER_STEP={}. Total sigs = {}",
            N_STEPS,
            SIGS_PER_STEP,
            N_STEPS * SIGS_PER_STEP
        );
        println!(
            "SIGS PER SECOND: {:?}",
            (N_STEPS * SIGS_PER_STEP) as f64 / t.as_secs_f64()
        );
        println!(
            "TIME FOR EACH SIG: {:?} ms",
            t / (N_STEPS * SIGS_PER_STEP) as u32
        );

        // verify the last IVC proof
        let ivc_proof = nova.ivc_proof();
        FS::<SIGS_PER_STEP>::verify(
            nova_params.1.clone(), // Nova's verifier params
            ivc_proof,
        )
        .unwrap();
    }
}
