use base64::{engine::general_purpose::STANDARD, Engine as _};
use pq_composite_sig::mldsa87_ed448::SigningKey; // Use qualified names from your crate
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;
use std::fs;

#[test]
fn test_composite_vectors() {
    let json_content =
        fs::read_to_string("tests/test_vectors.json").expect("Failed to read test_vectors.json");
    let data: Value = serde_json::from_str(&json_content).expect("Invalid JSON");

    let global_message_b64 = data["m"].as_str().expect("Missing global message 'm'");
    let message = STANDARD
        .decode(global_message_b64)
        .expect("Invalid base64 in global message");
    println!("Decoded message length: {}", message.len()); // Should be 44

    let tests = data["tests"].as_array().expect("Missing 'tests' array");
    let mut passed_count = 0;
    let mut skipped_count = 0;

    for test in tests {
        let tc_id = test["tcId"].as_str().unwrap_or("unknown");

        // Filter to only mldsa87_ed448 cases (adjust prefix if needed)
        if !tc_id.contains("mldsa87_ed448") {
            println!("Skipping unsupported variant: {}", tc_id);
            skipped_count += 1;
            continue;
        }
        println!("Running test: {}", tc_id);

        // Decode sk as raw bytes (expect 57 for Ed448 seed)
        let sk_b64 = test["sk"].as_str().expect("Missing 'sk' in test case");
        let sk_bytes: Vec<u8> = STANDARD.decode(sk_b64).expect("Invalid sk base64");
        println!("Decoded sk length: {}", sk_bytes.len()); // Debug: Check actual len

        // Assert length and convert to fixed array (adjust 57 if composite seed is 89)
        assert_eq!(
            sk_bytes.len(),
            57,
            "Seed length mismatch for {}: expected 57, got {}",
            tc_id,
            sk_bytes.len()
        );
        let sk_seed: [u8; 57] = sk_bytes.try_into().expect("sk must be 57 bytes");

        // Decode expected pk and sig (raw bytes)
        let expected_pk_b64 = test["pk"].as_str().expect("Missing 'pk'");
        let expected_sig_b64 = test["s"].as_str().expect("Missing 's'");
        let expected_pk = STANDARD.decode(expected_pk_b64).expect("Invalid pk base64");
        let expected_sig = STANDARD.decode(expected_sig_b64).expect("Invalid s base64");

        // Create signing key from seed
        let sk = SigningKey::new(sk_seed); // Your lib's constructor
        let vk = sk.verifying_key();

        // Verify public key matches (raw bytes)
        assert_eq!(
            vk.to_bytes().to_vec(),
            expected_pk,
            "Public key mismatch in {}",
            tc_id
        );
        println!("Public key match OK for {}", tc_id);

        // Deterministic RNG (all-zeroes)
        struct ZeroRng;
        impl RngCore for ZeroRng {
            fn next_u32(&mut self) -> u32 {
                0
            }
            fn next_u64(&mut self) -> u64 {
                0
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                dest.fill(0);
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl CryptoRng for ZeroRng {}

        let mut rng = ZeroRng;
        let sig = sk.sign(&message, &[], &mut rng).expect("Signing failed"); // Empty context

        // Verify signature matches (full composite bytes)
        assert_eq!(
            sig.to_bytes().to_vec(),
            expected_sig,
            "Signature mismatch in {}",
            tc_id
        );
        println!("Signature match OK for {}", tc_id);

        // Final verification check (empty context)
        vk.verify(&message, &sig, &[]).expect("Verification failed");
        println!("Verification OK for {}", tc_id);

        passed_count += 1;
    }

    println!(
        "Test complete: {} passed, {} skipped (unsupported variants).",
        passed_count, skipped_count
    );
    assert_eq!(
        skipped_count + passed_count,
        tests.len(),
        "All tests should be accounted for"
    ); // Optional: Enforce full coverage
}
