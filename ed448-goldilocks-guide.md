To use the **`ed448-goldilocks`** crate for signing (RFC 8032-compliant Ed448 signatures), follow these steps.

### 1. Add to Cargo.toml
```toml
[dependencies]
ed448-goldilocks = { version = "0.2", features = ["signing"] }  # Enable signing/verification
rand = { version = "0.8", features = ["std_rng"] }               # For key generation
```

### 2. Basic Signing and Verification Example
```rust
use ed448_goldilocks::{SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;  // Or any rand_core::RngCore

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a random signing key (includes private + public)
    let signing_key = SigningKey::generate(&mut OsRng)?;

    // Derive the corresponding verifying key (public key)
    let verifying_key = signing_key.verifying_key();

    // Message to sign
    let message = b"Hello, world! This is an Ed448 signature.";

    // Sign the message (PureEd448 mode – standard RFC 8032, no context, no prehash)
    let signature: Signature = signing_key.sign_raw(message);

    // Verify the signature
    assert!(verifying_key.verify_raw(&signature, message).is_ok());

    // Tampered message fails verification
    assert!(verifying_key.verify_raw(&signature, b"tampered message").is_err());

    println!("Ed448 signature successful!");
    Ok(())
}
```

### 3. Key Formats
- **Private key (seed)**: 57 bytes (the pre-hashed secret seed).
- **Public key**: 57 bytes (compressed Edwards Y coordinate + sign bit).
- **Signature**: 114 bytes (R || S, each 57 bytes).

```rust
// Export raw bytes
let secret_seed = signing_key.to_bytes();           // 57-byte private seed
let public_bytes = verifying_key.to_bytes();        // 57-byte public key
let sig_bytes = signature.to_bytes();               // 114-byte signature

// Import from raw bytes
let signing_key2 = SigningKey::from_bytes(&secret_seed)?;
let verifying_key2 = VerifyingKey::from_bytes(&public_bytes)?;
```

### 4. Advanced: Context and Prehashed (Ed448ph)
```rust
use ed448_goldilocks::{Context, PreHasherXof};
use sha3::{Shake256, digest::Update};

// With context (domain separation)
let context = Context::new(b"MyApp v1.0")?;  // Up to 255 bytes
let signature_with_ctx = signing_key.sign_raw_with_context(message, context);

// Prehashed mode (Ed448ph – hash message first)
let prehash = Shake256::default().chain(message).finalize_xof();
let signature_ph = signing_key.sign_prehashed::<PreHasherXof<Shake256>>(
    None,          // No context (or Some(context))
    prehash,
)?;

// Verify accordingly
verifying_key.verify_prehashed::<PreHasherXof<Shake256>>(
    &signature_ph,
    None,
    Shake256::default().chain(message).finalize_xof(),
)?;
```

### 5. Integration with `signature` Crate Traits
```rust
use signature::{Signer, Verifier};

let signature: Signature = signing_key.sign(message);  // Implements Signer
assert!(verifying_key.verify(message, &signature).is_ok());  // Implements Verifier
```

### Summary
- Use `SigningKey::generate(&mut rng)` for new keys.
- Use `sign_raw()` for standard PureEd448 (most common).
- Use contexts/prehash only if your protocol requires them.
- All operations are constant-time and compliant with RFC 8032 / FIPS 186-5 Ed448.

This crate is production-ready for most use cases (especially non-FIPS-validated environments). If you need certified FIPS compliance, pair it with OpenSSL's Ed448 instead. Otherwise, this is clean, fast, and idiomatic Rust.
