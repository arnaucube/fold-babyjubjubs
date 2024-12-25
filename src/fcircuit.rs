use ark_crypto_primitives::sponge::{poseidon::PoseidonConfig, Absorb};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::prelude::CurveVar;
use ark_r1cs_std::{
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{marker::PhantomData, Zero};
use core::borrow::Borrow;
use std::fmt::Debug;

use arkeddsa::{constraints::verify, signature::Signature, PublicKey};
use folding_schemes::{frontend::FCircuit, Error};

pub type CF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// Test circuit to be folded
#[derive(Clone, Debug)]
pub struct FoldSigsStepCircuit<
    F: PrimeField,
    C: CurveGroup,
    GC: CurveVar<C, F>,
    const SIGS_PER_STEP: usize,
> {
    _c: PhantomData<C>,
    _gc: PhantomData<GC>,
    config: PoseidonConfig<F>,
}
impl<F: PrimeField, C: CurveGroup, GC: CurveVar<C, F>, const SIGS_PER_STEP: usize> FCircuit<F>
    for FoldSigsStepCircuit<F, C, GC, SIGS_PER_STEP>
where
    F: Absorb,
    C: CurveGroup<BaseField = F>,
{
    type Params = PoseidonConfig<F>;
    type ExternalInputs = VecExtInp<C, SIGS_PER_STEP>;
    type ExternalInputsVar = VecExtInpVar<C, GC, SIGS_PER_STEP>;

    fn new(config: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            _c: PhantomData,
            _gc: PhantomData,
            config,
        })
    }
    fn state_len(&self) -> usize {
        1
    }
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut count = z_i[0].clone();
        for i in 0..SIGS_PER_STEP {
            let e = external_inputs.0[i].clone();
            let res = verify::<C, GC>(
                cs.clone(),
                self.config.clone(),
                e.pk,
                (e.sig_r, e.sig_s),
                e.msg,
            )?;
            res.enforce_equal(&Boolean::<F>::TRUE)?;
            count = count.clone() + FpVar::<F>::one();
        }

        Ok(vec![count])
    }
}

// recall, here C = ed_on_bn254, so C::BaseField = BN254::ScalarField
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ExtInp<C: CurveGroup> {
    msg: CF<C>,
    pk: PublicKey<C>,
    sig: Signature<C>,
}
impl<C: CurveGroup> Default for ExtInp<C> {
    fn default() -> Self {
        Self {
            msg: CF::<C>::zero(),
            pk: PublicKey(C::zero().into_affine()),
            sig: Signature::new(C::zero().into_affine(), C::ScalarField::zero()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct VecExtInp<C: CurveGroup, const SIGS_PER_STEP: usize>(Vec<ExtInp<C>>);
impl<C: CurveGroup, const SIGS_PER_STEP: usize> Default for VecExtInp<C, SIGS_PER_STEP> {
    fn default() -> Self {
        VecExtInp(vec![ExtInp::default(); SIGS_PER_STEP])
    }
}

#[derive(Clone, Debug)]
pub struct ExtInpVar<C: CurveGroup, GC: CurveVar<C, CF<C>>> {
    msg: FpVar<CF<C>>,
    pk: GC,
    sig_r: GC,
    sig_s: Vec<Boolean<CF<C>>>,
}
impl<C: CurveGroup, GC: CurveVar<C, CF<C>>> Default for ExtInpVar<C, GC> {
    fn default() -> Self {
        Self {
            msg: FpVar::<CF<C>>::zero(),
            pk: GC::zero(),
            sig_r: GC::zero(),
            sig_s: vec![Boolean::<CF<C>>::FALSE; 253], // TODO 253-> fieldbitsize
        }
    }
}

#[derive(Clone, Debug)]
pub struct VecExtInpVar<C: CurveGroup, GC: CurveVar<C, CF<C>>, const SIGS_PER_STEP: usize>(
    Vec<ExtInpVar<C, GC>>,
);
impl<C: CurveGroup, GC: CurveVar<C, CF<C>>, const SIGS_PER_STEP: usize> Default
    for VecExtInpVar<C, GC, SIGS_PER_STEP>
{
    fn default() -> Self {
        VecExtInpVar(vec![ExtInpVar::default(); SIGS_PER_STEP])
    }
}

impl<C, GC, const SIGS_PER_STEP: usize> AllocVar<VecExtInp<C, SIGS_PER_STEP>, CF<C>>
    for VecExtInpVar<C, GC, SIGS_PER_STEP>
where
    C: CurveGroup,
    GC: CurveVar<C, CF<C>>,
{
    fn new_variable<T: Borrow<VecExtInp<C, SIGS_PER_STEP>>>(
        cs: impl Into<Namespace<CF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();

            let mut v = vec![];
            for e in val.borrow().0.iter() {
                let msg = FpVar::<CF<C>>::new_variable(cs.clone(), || Ok(e.msg), mode)?;
                let pk = GC::new_variable(cs.clone(), || Ok(e.pk.0), mode)?;
                let sig_r = GC::new_variable(cs.clone(), || Ok(e.sig.r), mode)?;
                let sig_s = Vec::<Boolean<CF<C>>>::new_variable(
                    cs.clone(),
                    || Ok(e.sig.s.into_bigint().to_bits_le()),
                    mode,
                )?;
                v.push(ExtInpVar {
                    msg,
                    pk,
                    sig_r,
                    sig_s,
                });
            }

            Ok(Self(v))
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ec::AdditiveGroup;
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::Rng;
    use rand_core::CryptoRngCore;
    use std::str::FromStr;

    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    use arkeddsa::{
        ed_on_bn254_twist::{constraints::EdwardsVar, EdwardsProjective},
        SigningKey,
    };

    pub fn gen_signatures<R: Rng + CryptoRngCore, const SIGS_PER_STEP: usize>(
        rng: &mut R,
        poseidon_config: &PoseidonConfig<Fr>,
        steps: usize,
    ) -> Vec<VecExtInp<EdwardsProjective, SIGS_PER_STEP>> {
        let mut r = vec![];
        for _ in 0..steps {
            let mut res: Vec<ExtInp<EdwardsProjective>> = Vec::new();
            for _ in 0..SIGS_PER_STEP {
                let sk =
                    SigningKey::<EdwardsProjective>::generate::<blake2::Blake2b512>(rng).unwrap();
                let msg = Fr::from_str("12345").unwrap();
                let sig = sk
                    .sign::<blake2::Blake2b512>(&poseidon_config, &msg)
                    .unwrap();
                let pk = sk.public_key();
                pk.verify(&poseidon_config, &msg, &sig).unwrap();
                res.push(ExtInp {
                    msg,
                    pk: pk.clone(),
                    sig,
                });
            }
            r.push(VecExtInp(res));
        }
        r
    }

    #[test]
    fn test_sig() {
        const SIGS_PER_STEP: usize = 10;
        let mut rng = rand::rngs::OsRng;
        let poseidon_config = poseidon_canonical_config::<Fr>();

        const N: usize = 1;
        let ext_inps =
            gen_signatures::<rand::rngs::OsRng, SIGS_PER_STEP>(&mut rng, &poseidon_config, 1);
        let e = ext_inps[0].0[0].clone();
        e.pk.verify(&poseidon_config, &e.msg, &e.sig).unwrap();
    }

    fn ensure_fcircuit_trait<FC: FCircuit<Fr>>(params: FC::Params) {
        let _ = FC::new(params);
    }

    // test to check that the Sha256FCircuit computes the same values inside and outside the circuit
    #[test]
    fn test_fcircuit() {
        const SIGS_PER_STEP: usize = 10;
        let mut rng = rand::rngs::OsRng;
        let poseidon_config = poseidon_canonical_config::<Fr>();

        let ext_inps =
            gen_signatures::<rand::rngs::OsRng, SIGS_PER_STEP>(&mut rng, &poseidon_config, 1);
        let ext_inps = ext_inps[0].clone();

        // here `Fr` is the BN254::G1::Fr = ed_on_bn254_twist::EdwardsProjective::Fq
        let cs = ConstraintSystem::<Fr>::new_ref();

        type FC = FoldSigsStepCircuit<Fr, EdwardsProjective, EdwardsVar, SIGS_PER_STEP>;
        ensure_fcircuit_trait::<FC>(poseidon_config.clone());

        let circuit = FC::new(poseidon_config).unwrap();
        let z_i = vec![Fr::ZERO];

        let external_inputs_var =
            VecExtInpVar::<EdwardsProjective, EdwardsVar, SIGS_PER_STEP>::new_witness(
                cs.clone(),
                || Ok(ext_inps),
            )
            .unwrap();

        let z_iVar = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z_i)).unwrap();
        let computed_z_i1Var = circuit
            .generate_step_constraints(cs.clone(), 0, z_iVar.clone(), external_inputs_var)
            .unwrap();
        assert_eq!(
            computed_z_i1Var.value().unwrap(),
            vec![Fr::from(SIGS_PER_STEP as u32)]
        );
        assert!(cs.is_satisfied().unwrap());
        dbg!(cs.num_constraints());
        dbg!(&computed_z_i1Var.value().unwrap());
    }
}
