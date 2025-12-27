# Implementing Draft-Compliant Composite ML-DSA Signatures in Rust

This document provides a complete guide for Zed-Grok AI to implement the **IETF LAMPS composite ML-DSA signatures** (draft-ietf-lamps-pq-composite-sigs-13, October 2025) in a new Rust crate named **`pq-xwing-sig`**.

We'll start with the **strongest variant**: **ML-DSA-87 + Ed448** (the only Ed448 pairing defined in the draft).

Later variants (ML-DSA-44 + Ed25519 and ML-DSA-65 + Ed25519) will follow the same pattern with minor changes (different parameters, SHA512 pre-hash).

## Problems with the Previous Attempted Implementation

Your earlier code (the "X-Wing"-style version with custom binding tag) had several critical issues that prevented draft compliance:

- **Wrong pairing and security level**: Used **ML-DSA-87 + Ed25519** (~128-bit classical security). The draft **explicitly pairs ML-DSA-87 only with Ed448** (~224-bit) for balanced strength. Ed25519 is reserved for lower ML-DSA levels (44/65).
- **Custom binding mechanism**: Used a post-signing SHA3-256 tag over both signatures + message hash ("X-Wing-SIG" label). This is a custom construction (inspired by KEM combiners) not in the draft.
- **Draft binding is implicit**: Both components sign the **same domain-separated pre-hashed message representative M'**. No extra tag needed — binding comes from shared input.
- **No pre-hashing/domain separation**: Signed raw message directly. The draft **requires** pre-hashing the message (SHAKE256 for Ed448 pairings) and constructing M' with fixed prefix + algorithm-specific label + optional context.
- **Wrong hash function**: Used SHA3-256 everywhere. Draft requires **SHAKE256** (512-bit output) for Ed448 pairings.
- **ML-DSA context empty**: Draft requires ML-DSA's `context` parameter set to the algorithm label (e.g., "MLDSA87-Ed448-SHAKE256").

These made it a solid custom hybrid but **not compliant** with the IETF draft.

## New Crate Setup: `pq-xwing-sig`

Update your `Cargo.toml`:

```toml
[package]
name = "pq-xwing-sig"
version = "0.1.0"
edition = "2021"  # or 2024 if you prefer
description = "Draft-compliant composite ML-DSA signatures (LAMPS WG)"
license = "MIT OR Apache-2.0"
repository = "https://github.com/yourname/pq-xwing-sig"  # optional
keywords = ["post-quantum", "composite", "ml-dsa", "ed448", "cryptography"]
categories = ["cryptography", "no-std"]

[dependencies]
libcrux-ml-dsa = { git = "https://github.com/cryspen/libcrux", package = "libcrux-ml-dsa", branch = "main" }
ed448-goldilocks = "0.5"  # Latest full Ed448 impl (pure Rust, supports signing/verification)
sha3 = "0.10"
zeroize = { version = "1.8", features = ["zeroize_derive"] }
rand_core = "0.6"
thiserror = "1.0"  # For better errors

[dev-dependencies]
rand = "0.8"  # For testing
```

**Note on Ed448 crate**: Use **`ed448-goldilocks = "0.5"`** (or latest) — it's the best pure-Rust full implementation available (supports Ed448 signing/verification with SHAKE256). The `ed448` crate is only traits/types.

## Module Structure

Create:
- `src/lib.rs` — re-exports and docs
- `src/mldsa87_ed448.rs` — the ML-DSA-87 + Ed448 implementation (copy the code below)

Future:
- `src/mldsa65_ed25519.rs`
- `src/mldsa44_ed25519.rs`

## Full Implementation: ML-DSA-87 + Ed448

Paste this into `src/mldsa87_ed448.rs`:

```rust
//! Draft-compliant composite ML-DSA-87 + Ed448 signatures
//! (draft-ietf-lamps-pq-composite-sigs-13)

use core::ops::Deref;

use ed448_goldilocks::{
    Ed448,
    Scalar as EdScalar,
    EdwardsPoint as EdPublicKey,
    Signature as EdSignature,
};

use libcrux_ml_dsa::ml_dsa_87::{
    generate_key_pair,
    sign as ml_dsa_sign,
    verify as ml_dsa_verify,
    MLDSA87KeyPair,
    MLDSA87Signature,
    MLDSA87VerificationKey,
};

use rand_core::{CryptoRng, RngCore};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MASTER_SEED_SIZE: usize = 89; // 32 (ML-DSA) + 57 (Ed448)

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
    vk_ed: EdPublicKey,
}

#[derive(ZeroizeOnDrop)]
pub struct SigningKey {
    seed: Zeroizing<[u8; MASTER_SEED_SIZE]>,
}

#[derive(Clone)]
pub struct Signature {
    sig_ml: MLDSA87Signature,
    sig_ed: EdSignature,
}

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

        Ed448::verify(&self.vk_ed, &m_prime, &signature.sig_ed)
            .map_err(|_| CompositeError::InvalidEdSignature)?;

        Ok(())
    }
}

impl SigningKey {
    pub fn new(seed: [u8; MASTER_SEED_SIZE]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
        }
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

        let (kp_ml, sk_ed) = expand_seed(&self.seed);
        let sk_ml = kp_ml.signing_key;

        let ph_m = compute_ph(message);
        let m_prime = compute_m_prime(&ph_m, context);

        let mut rand = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut rand);

        let sig_ml = ml_dsa_sign(&sk_ml, &m_prime, LABEL, *rand)
            .map_err(|_| CompositeError::MlDsaSignError)?;

        let sig_ed = Ed448::sign(&sk_ed, &m_prime);

        Ok(Signature { sig_ml, sig_ed })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        let (kp_ml, sk_ed) = expand_seed(&self.seed);
        VerifyingKey {
            vk_ml: kp_ml.verification_key,
            vk_ed: sk_ed.to_public(),
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
        let sig_ed = EdSignature::from_bytes(&sig_ed_bytes);

        Ok(Signature { sig_ml, sig_ed })
    }
}

pub fn generate_keypair<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> (SigningKey, VerifyingKey) {
    let mut seed = Zeroizing::new([0u8; MASTER_SEED_SIZE]);
    rng.fill_bytes(&mut seed);

    let sk = SigningKey::new(*seed);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn expand_seed(seed: &Zeroizing<[u8; MASTER_SEED_SIZE]>) -> (MLDSA87KeyPair, EdScalar) {
    let mut hasher = Shake256::default();
    hasher.update(seed.deref());
    let mut reader = hasher.finalize_xof();

    let mut expanded = Zeroizing::new([0u8; 89]);
    reader.read(&mut expanded);

    let ml_seed = Zeroizing::new(expanded[..32].try_into().unwrap());
    let ed_seed = Zeroizing::new(expanded[32..].try_into().unwrap());

    let kp_ml = generate_key_pair(*ml_seed);
    let sk_ed = EdScalar::from_bytes(&ed_seed);

    // Clean up
    drop(ml_seed);
    drop(ed_seed);
    drop(expanded);

    (kp_ml, sk_ed)
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
    let mut m_prime = Vec::with_capacity(DOM_SEP.len() + LABEL.len() + 1 + context.len() + PH_OUTPUT_LEN);
    m_prime.extend_from_slice(DOM_SEP);
    m_prime.extend_from_slice(LABEL);
    m_prime.push(context.len() as u8);
    m_prime.extend_from_slice(context);
    m_prime.extend_from_slice(ph_m);
    m_prime
}
```

## Next Steps

1. Implement this ML-DSA-87 + Ed448 module first.
2. Add tests using the draft's test vectors (Appendix E).
3. Then duplicate for:
   - ML-DSA-65 + Ed25519 (use `ed25519-dalek`, SHA512 pre-hash, label "MLDSA65-Ed25519-SHA512")
   - ML-DSA-44 + Ed25519 (same as above, different params)

This will give you a fully compliant, secure, and high-quality `pq-xwing-sig` crate.

Let me know when this is done — we'll move to the next variants!
