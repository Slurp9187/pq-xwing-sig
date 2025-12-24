#![allow(unused_imports)] // Temporary for compilation

//! Draft-compliant composite ML-DSA-87 + Ed448 signatures
//! (draft-ietf-lamps-pq-composite-sigs-13)

use core::ops::Deref;

use ed448_goldilocks_plus::{
    Signature as EdSignature, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};

use libcrux_ml_dsa::ml_dsa_87::{
    generate_key_pair, sign as ml_dsa_sign, verify as ml_dsa_verify, MLDSA87KeyPair,
    MLDSA87Signature, MLDSA87VerificationKey,
};

use rand_core::{CryptoRng, RngCore};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use signature::Verifier;
use std::fmt::{Debug, Formatter};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MASTER_SEED_SIZE: usize = 57; // Ed448 private key size

const ML_PK_SIZE: usize = 2592;
const ED_PK_SIZE: usize = 57;
pub const VERIFYING_KEY_SIZE: usize = ML_PK_SIZE + ED_PK_SIZE;

const ML_SIG_SIZE: usize = 4627;
const ED_SIG_SIZE: usize = 114;
pub const SIGNATURE_SIZE: usize = ML_SIG_SIZE + ED_SIG_SIZE;

const DOM_SEP: &[u8] = b"CompositeAlgorithmSignatures2025";
const LABEL: &[u8] = b"MLDSA87-Ed448-SHAKE256";
const PH_OUTPUT_LEN: usize = 64; // 512 bits

#[derive(Error, Debug)]
pub enum CompositeError {
    #[error("context too long (>255 bytes)")]
    InvalidContextLength,
    #[error("invalid signature length")]
    InvalidSignatureLength,
    #[error("invalid ML-DSA signature")]
    InvalidMlDsaSignature,
    #[error("invalid Ed448 signature")]
    InvalidEdSignature,
    #[error("ML-DSA signing failed")]
    MlDsaSignError,
}

#[derive(Clone)]
pub struct VerifyingKey {
    vk_ml: MLDSA87VerificationKey,
    vk_ed: EdVerifyingKey,
}

impl Debug for VerifyingKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("vk_ml", &"..")
            .field("vk_ed", &"..")
            .finish()
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for VerifyingKey {}

#[derive(ZeroizeOnDrop)]
pub struct SigningKey {
    sk_ed: EdSigningKey,
}

impl Debug for SigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey").field("sk_ed", &"..").finish()
    }
}

#[derive(Clone)]
pub struct Signature {
    sig_ml: MLDSA87Signature,
    sig_ed: EdSignature,
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("sig_ml", &"..")
            .field("sig_ed", &"..")
            .finish()
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for Signature {}

impl VerifyingKey {
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_SIZE] {
        let mut buf = [0u8; VERIFYING_KEY_SIZE];
        buf[..ML_PK_SIZE].copy_from_slice(self.vk_ml.as_ref());
        buf[ML_PK_SIZE..].copy_from_slice(&self.vk_ed.to_bytes());
        buf
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        context: &[u8],
    ) -> Result<(), CompositeError> {
        if context.len() > 255 {
            return Err(CompositeError::InvalidContextLength);
        }

        let ph_m = compute_ph(message);
        let m_prime = compute_m_prime(&ph_m, context);

        ml_dsa_verify(&self.vk_ml, &m_prime, LABEL, &signature.sig_ml)
            .map_err(|_| CompositeError::InvalidMlDsaSignature)?;

        self.vk_ed
            .verify(&m_prime, &signature.sig_ed)
            .map_err(|_| CompositeError::InvalidEdSignature)?;

        Ok(())
    }
}

impl From<&[u8; VERIFYING_KEY_SIZE]> for VerifyingKey {
    fn from(bytes: &[u8; VERIFYING_KEY_SIZE]) -> Self {
        let vk_ml_bytes: [u8; ML_PK_SIZE] = bytes[..ML_PK_SIZE].try_into().unwrap();
        let vk_ml = MLDSA87VerificationKey::new(vk_ml_bytes);
        let vk_ed_bytes: [u8; ED_PK_SIZE] = bytes[ML_PK_SIZE..].try_into().unwrap();
        let vk_ed = EdVerifyingKey::from_bytes(&vk_ed_bytes).unwrap();
        Self { vk_ml, vk_ed }
    }
}

impl SigningKey {
    pub fn new(seed: [u8; MASTER_SEED_SIZE]) -> Self {
        let sk_ed = EdSigningKey::try_from(&seed[..]).unwrap();
        Self { sk_ed }
    }

    pub fn sign(
        &self,
        message: &[u8],
        context: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Signature, CompositeError> {
        if context.len() > 255 {
            return Err(CompositeError::InvalidContextLength);
        }

        let ed_seed_bytes = self.sk_ed.to_bytes();
        let ed_seed_array: [u8; MASTER_SEED_SIZE] = (&*ed_seed_bytes).try_into().unwrap();
        let kp_ml = expand_seed(&ed_seed_array);
        let sk_ml = kp_ml.signing_key;

        let ph_m = compute_ph(message);
        let m_prime = compute_m_prime(&ph_m, context);

        let mut rand = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *rand);

        let sig_ml = ml_dsa_sign(&sk_ml, &m_prime, LABEL, *rand)
            .map_err(|_| CompositeError::MlDsaSignError)?;

        let sig_ed = self.sk_ed.sign_raw(&m_prime);

        Ok(Signature { sig_ml, sig_ed })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        let ed_seed_bytes = self.sk_ed.to_bytes();
        let ed_seed_array: [u8; MASTER_SEED_SIZE] = (&*ed_seed_bytes).try_into().unwrap();
        let kp_ml = expand_seed(&ed_seed_array);
        let vk_ed = self.sk_ed.verifying_key();
        VerifyingKey {
            vk_ml: kp_ml.verification_key,
            vk_ed,
        }
    }
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut buf = [0u8; SIGNATURE_SIZE];
        buf[..ML_SIG_SIZE].copy_from_slice(self.sig_ml.as_ref());
        buf[ML_SIG_SIZE..].copy_from_slice(&self.sig_ed.to_bytes());
        buf
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = CompositeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CompositeError::InvalidSignatureLength);
        }

        let mut sig_ml_bytes = [0u8; ML_SIG_SIZE];
        sig_ml_bytes.copy_from_slice(&bytes[..ML_SIG_SIZE]);
        let sig_ml = MLDSA87Signature::new(sig_ml_bytes);

        let mut sig_ed_bytes = [0u8; ED_SIG_SIZE];
        sig_ed_bytes.copy_from_slice(&bytes[ML_SIG_SIZE..]);
        let sig_ed = EdSignature::from_bytes(&sig_ed_bytes).unwrap();

        Ok(Signature { sig_ml, sig_ed })
    }
}

pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (SigningKey, VerifyingKey) {
    let sk_ed = EdSigningKey::generate(rng);
    let sk = SigningKey { sk_ed };
    let vk = sk.verifying_key();
    (sk, vk)
}

fn expand_seed(ed_seed: &[u8; MASTER_SEED_SIZE]) -> MLDSA87KeyPair {
    let mut hasher = Shake256::default();
    hasher.update(ed_seed);
    let mut reader = hasher.finalize_xof();
    let mut ml_seed = [0u8; 32];
    reader.read(&mut ml_seed);
    generate_key_pair(ml_seed)
}

fn compute_ph(message: &[u8]) -> [u8; PH_OUTPUT_LEN] {
    let mut hasher = Shake256::default();
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; PH_OUTPUT_LEN];
    reader.read(&mut output);
    output
}

fn compute_m_prime(ph_m: &[u8; PH_OUTPUT_LEN], context: &[u8]) -> Vec<u8> {
    let mut m_prime =
        Vec::with_capacity(DOM_SEP.len() + LABEL.len() + 1 + context.len() + PH_OUTPUT_LEN);
    m_prime.extend_from_slice(DOM_SEP);
    m_prime.extend_from_slice(LABEL);
    m_prime.push(context.len() as u8);
    m_prime.extend_from_slice(context);
    m_prime.extend_from_slice(ph_m);
    m_prime
}
