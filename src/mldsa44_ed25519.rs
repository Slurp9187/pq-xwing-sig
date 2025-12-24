#![allow(unused_imports)] // Temporary for compilation

//! Draft-compliant composite ML-DSA-44 + Ed25519 signatures
//! (draft-ietf-lamps-pq-composite-sigs-13)

use core::ops::Deref;

use ed25519_dalek::{
    Signature as EdSignature, Signer, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};

use libcrux_ml_dsa::ml_dsa_44::{
    generate_key_pair, sign as ml_dsa_sign, verify as ml_dsa_verify, MLDSA44KeyPair,
    MLDSA44Signature, MLDSA44VerificationKey,
};

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
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

pub const ML_PK_SIZE: usize = 1312;
pub const ED_PK_SIZE: usize = 32;
pub const VERIFYING_KEY_SIZE: usize = ML_PK_SIZE + ED_PK_SIZE;

pub const ML_SIG_SIZE: usize = 2420;
pub const ED_SIG_SIZE: usize = 64;
pub const SIGNATURE_SIZE: usize = ML_SIG_SIZE + ED_SIG_SIZE;

const DOM_SEP: &[u8] = b"CompSigX962-2023";
const LABEL: &[u8] = b"SigMLDSA44";
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
    vk_ml: MLDSA44VerificationKey,
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

pub struct SigningKey {
    sk_ml: MLDSA44KeyPair,
    sk_ed: EdSigningKey,
}

impl Debug for SigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("sk_ml", &"..")
            .field("sk_ed", &"..")
            .finish()
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
    sig_ml: MLDSA44Signature,
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

        let m_prime_hash = Sha512::digest(&m_prime);
        self.vk_ed
            .verify(&m_prime_hash, &signature.sig_ed)
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
        let vk_ml = MLDSA44VerificationKey::new(vk_ml_bytes);
        let vk_ed_bytes: [u8; ED_PK_SIZE] = bytes[ML_PK_SIZE..].try_into().unwrap();
        let vk_ed = EdVerifyingKey::try_from(&vk_ed_bytes[..])
            .map_err(|_| CompositeError::InvalidVerifyingKeyBytes)?;
        Ok(Self { vk_ml, vk_ed })
    }
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = CompositeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != VERIFYING_KEY_SIZE {
            return Err(CompositeError::InvalidVerifyingKeyBytes);
        }
        let bytes_array: &[u8; VERIFYING_KEY_SIZE] = bytes.try_into().unwrap();
        Self::try_from(bytes_array)
    }
}

impl SigningKey {
    pub fn new(seed: [u8; MASTER_SEED_SIZE]) -> Self {
        let sk_ed = EdSigningKey::from_bytes(&seed);
        let sk_ml = expand_seed(&seed);
        Self { sk_ml, sk_ed }
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        let mut sk_ml_bytes = [0u8; 32];
        sk_ml_bytes.copy_from_slice(&bytes[..32]);
        let sk_ml = generate_key_pair(sk_ml_bytes);
        let mut sk_ed_bytes = [0u8; 32];
        sk_ed_bytes.copy_from_slice(&bytes[32..]);
        let sk_ed = EdSigningKey::from_bytes(&sk_ed_bytes);
        Self { sk_ml, sk_ed }
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

        let ph_m = compute_ph(message);
        let m_prime = compute_m_prime(&ph_m, context);

        let mut rand = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *rand);

        let sig_ml = ml_dsa_sign(&self.sk_ml.signing_key, &m_prime, LABEL, *rand)
            .map_err(|_| CompositeError::MlDsaSignError)?;

        let m_prime_hash = Sha512::digest(&m_prime);
        let sig_ed = self.sk_ed.sign(&m_prime_hash);

        Ok(Signature { sig_ml, sig_ed })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        let vk_ed = self.sk_ed.verifying_key();
        VerifyingKey {
            vk_ml: self.sk_ml.verification_key.clone(),
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
        let sig_ml = MLDSA44Signature::new(sig_ml_bytes);

        let mut sig_ed_bytes = [0u8; ED_SIG_SIZE];
        sig_ed_bytes.copy_from_slice(&bytes[ML_SIG_SIZE..]);
        let sig_ed = EdSignature::try_from(sig_ed_bytes.as_ref())
            .map_err(|_| CompositeError::InvalidSignatureBytes)?;

        Ok(Signature { sig_ml, sig_ed })
    }
}

impl TryFrom<&[u8; SIGNATURE_SIZE]> for Signature {
    type Error = CompositeError;

    fn try_from(bytes: &[u8; SIGNATURE_SIZE]) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (SigningKey, VerifyingKey) {
    let sk_ed = EdSigningKey::generate(rng);
    let mut ml_seed = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *ml_seed);
    let sk_ml = generate_key_pair(*ml_seed);
    let sk = SigningKey { sk_ml, sk_ed };
    let vk = sk.verifying_key();
    (sk, vk)
}

fn expand_seed(ed_seed: &[u8; MASTER_SEED_SIZE]) -> MLDSA44KeyPair {
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
