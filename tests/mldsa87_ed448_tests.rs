use pq_composite_sig::mldsa87_ed448::*;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
// Deterministic RNG for reproducible tests
fn test_rng() -> ChaCha12Rng {
    ChaCha12Rng::from_seed([42u8; 32])
}
#[test]
fn test_generate_keypair() {
    let mut rng = test_rng();
    let (sk, vk) = generate_keypair(&mut rng);
    assert_eq!(sk.verifying_key().to_bytes(), vk.to_bytes());
}
#[test]
fn test_sign_verify_roundtrip() {
    let mut rng = test_rng();
    let (sk, vk) = generate_keypair(&mut rng);
    let message = b"Hello, post-quantum world!";
    let context = b"test_context";
    let sig = sk.sign(message, context, &mut rng).unwrap();
    assert!(vk.verify(message, &sig, context).is_ok());
}
#[test]
fn test_verify_invalid_message() {
    let mut rng = test_rng();
    let (sk, vk) = generate_keypair(&mut rng);
    let message = b"Hello, post-quantum world!";
    let wrong_message = b"Goodbye, classical crypto!";
    let context = b"test_context";
    let sig = sk.sign(message, context, &mut rng).unwrap();
    assert!(vk.verify(wrong_message, &sig, context).is_err());
}
#[test]
fn test_verify_invalid_context() {
    let mut rng = test_rng();
    let (sk, vk) = generate_keypair(&mut rng);
    let message = b"Hello, post-quantum world!";
    let context = b"test_context";
    let wrong_context = b"wrong_context";
    let sig = sk.sign(message, context, &mut rng).unwrap();
    assert!(vk.verify(message, &sig, wrong_context).is_err());
}
#[test]
fn test_verify_tampered_signature() {
    let mut rng = test_rng();
    let (sk, vk) = generate_keypair(&mut rng);
    let message = b"Hello, post-quantum world!";
    let context = b"test_context";
    let sig = sk.sign(message, context, &mut rng).unwrap();
    let mut sig_bytes = sig.to_bytes();
    sig_bytes[1] ^= 1; // Flip a bit in ML-DSA sig
    let tampered_sig = Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(vk.verify(message, &tampered_sig, context).is_err());
}
#[test]
fn test_invalid_context_length() {
    let mut rng = test_rng();
    let (sk, _) = generate_keypair(&mut rng);
    let message = b"Hello, post-quantum world!";
    let long_context = vec![0u8; 256]; // >255 bytes
    assert!(sk.sign(message, &long_context, &mut rng).is_err());
}
#[test]
fn test_serialization_roundtrip() {
    let mut rng = test_rng();
    let (sk, vk) = generate_keypair(&mut rng);
    let message = b"Hello, post-quantum world!";
    let context = b"test_context";
    let sig = sk.sign(message, context, &mut rng).unwrap();
    let vk_bytes = vk.to_bytes();
    let sig_bytes = sig.to_bytes();
    let vk_deserialized = VerifyingKey::from(&vk_bytes);
    let sig_deserialized = Signature::try_from(&sig_bytes[..]).unwrap();
    assert_eq!(vk.to_bytes(), vk_deserialized.to_bytes());
    assert_eq!(sig.to_bytes(), sig_deserialized.to_bytes());
    assert!(
        vk_deserialized
            .verify(message, &sig_deserialized, context)
            .is_ok()
    );
}
#[test]
fn test_deterministic_keys_from_seed() {
    let seed = [1u8; 57]; // Updated to 57 bytes
    let sk1 = SigningKey::new(seed);
    let sk2 = SigningKey::new(seed);
    let vk1 = sk1.verifying_key();
    let vk2 = sk2.verifying_key();
    assert_eq!(vk1.to_bytes(), vk2.to_bytes());
}
#[test]
fn test_verify_wrong_key() {
    let mut rng = test_rng();
    let (sk, vk) = generate_keypair(&mut rng);
    let (_, wrong_vk) = generate_keypair(&mut rng);
    let message = b"Hello, post-quantum world!";
    let context = b"test_context";
    let sig = sk.sign(message, context, &mut rng).unwrap();
    assert!(vk.verify(message, &sig, context).is_ok());
    assert!(wrong_vk.verify(message, &sig, context).is_err());
}
// TODO: Add draft test vectors (Appendix E) here
