#![allow(unused_imports)] // Temporary for compilation

//! Draft-compliant composite ML-DSA-65 + Ed25519 signatures
//! (draft-ietf-lamps-pq-composite-sigs-13)

use core::ops::Deref;

use ed25519_dalek::{SignatureError, Signer};

use libcrux_ml_dsa::ml_dsa_65::{
    generate_key_pair, sign as ml_dsa_sign, verify as ml_dsa_verify, MLDSA65KeyPair,
    MLDSA65Signature, MLDSA65VerificationKey,
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

const MASTER_SEED_SIZE: usize = 32; // Ed25519 private key seed size

const ML_PK_SIZE: usize = 1952;
const ED_PK_SIZE: usize = 32;
pub const VERIFYING_KEY_SIZE: usize = ML_PK_SIZE + ED_PK_SIZE;

const ML_SIG_SIZE: usize = 3309;
const ED_SIG_SIZE: usize = 64;
pub const SIGNATURE_SIZE: usize = ML_SIG_SIZE + ED_SIG_SIZE;

const DOM_SEP: &[u8] = b"CompositeAlgorithmSignatures2025";
const LABEL: &[u8] = b"MLDSA65-Ed25519-SHAKE256";
const PH_OUTPUT_LEN: usize = 64; // 512 bits

#[derive(Error, Debug)]
pub enum CompositeError {
    #[error("context too long (>255 bytes)")]
    InvalidContextLength,
    #[error("invalid signature length")]
    InvalidSignatureLength,
    #[error("invalid signature bytes")]
    InvalidSignatureBytes,
    #[error("invalid verifying key bytes")]
    InvalidVerifyingKeyBytes,
    #[error("invalid ML-DSA signature")]
    InvalidMlDsaSignature,
    #[error("invalid Ed25519 signature")]
    InvalidEdSignature,
    #[error("ML-DSA signing failed")]
    MlDsaSignError,
}

impl From<ed25519_dalek::SignatureError> for CompositeError {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        CompositeError::InvalidSignatureBytes
    }
}

#[derive(Clone)]
pub struct VerifyingKey {
    vk_ml: MLDSA65VerificationKey,
    vk_ed: ed25519_dalek::VerifyingKey,
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
    sk_ed: ed25519_dalek::SigningKey,
}

impl Debug for SigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey").field("sk_ed", &"..").finish()
    }
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        self.verifying_key() == other.verifying_key()
    }
}

impl Eq for SigningKey {}

#[derive(Clone)]
pub struct Signature {
    sig_ml: MLDSA65Signature,
    sig_ed: ed25519_dalek::Signature,
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

impl TryFrom<&[u8; VERIFYING_KEY_SIZE]> for VerifyingKey {
    type Error = CompositeError;

    fn try_from(bytes: &[u8; VERIFYING_KEY_SIZE]) -> Result<Self, Self::Error> {
        let vk_ml_bytes: [u8; ML_PK_SIZE] = bytes[..ML_PK_SIZE]
            .try_into()
            .map_err(|_| CompositeError::InvalidVerifyingKeyBytes)?;
        let vk_ml = MLDSA65VerificationKey::new(vk_ml_bytes);
        let vk_ed_bytes: [u8; ED_PK_SIZE] = bytes[ML_PK_SIZE..].try_into().unwrap();
        let vk_ed = ed25519_dalek::VerifyingKey::try_from(&vk_ed_bytes[..])
            .map_err(|_| CompositeError::InvalidVerifyingKeyBytes)?;
        Ok(Self { vk_ml, vk_ed })
    }
}

impl SigningKey {
    pub fn new(seed: [u8; MASTER_SEED_SIZE]) -> Self {
        let sk_ed = ed25519_dalek::SigningKey::from_bytes(&seed);
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
        let ed_seed_array = Zeroizing::new(ed_seed_bytes); // Already [u8; 32]
        let kp_ml = expand_seed(&*ed_seed_array);
        let sk_ml = kp_ml.signing_key;

        let ph_m = compute_ph(message);
        let m_prime = compute_m_prime(&ph_m, context);

        let mut rand = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *rand);

        let sig_ml = ml_dsa_sign(&sk_ml, &m_prime, LABEL, *rand)
            .map_err(|_| CompositeError::MlDsaSignError)?;

        let sig_ed = self.sk_ed.sign(&m_prime);

        Ok(Signature { sig_ml, sig_ed })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        let ed_seed_bytes = self.sk_ed.to_bytes();
        let ed_seed_array = Zeroizing::new(ed_seed_bytes);
        let kp_ml = expand_seed(&*ed_seed_array);
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
        let sig_ml = MLDSA65Signature::new(sig_ml_bytes);

        let mut sig_ed_bytes = [0u8; ED_SIG_SIZE];
        sig_ed_bytes.copy_from_slice(&bytes[ML_SIG_SIZE..]);
        let sig_ed = ed25519_dalek::Signature::try_from(sig_ed_bytes.as_ref())?;

        Ok(Signature { sig_ml, sig_ed })
    }
}

pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (SigningKey, VerifyingKey) {
    let sk_ed = ed25519_dalek::SigningKey::generate(rng);
    let sk = SigningKey { sk_ed };
    let vk = sk.verifying_key();
    (sk, vk)
}

fn expand_seed(ed_seed: &[u8; MASTER_SEED_SIZE]) -> MLDSA65KeyPair {
    let mut hasher = Shake256::default();
    hasher.update(ed_seed);
    let mut reader = hasher.finalize_xof();
    let mut ml_seed = Zeroizing::new([0u8; 32]);
    reader.read(&mut *ml_seed);
    generate_key_pair(*ml_seed)
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
