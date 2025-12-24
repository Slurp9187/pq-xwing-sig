#[cfg(test)]
mod old_r5_cert_verify {
    use pq_composite_sig::mldsa44_ed25519::{
        CompositeError, Signature, VerifyingKey,
    };
    use libcrux_ml_dsa::ml_dsa_44::verify as ml_dsa_verify;

    use sha2::{Digest, Sha512};
    use x509_parser::prelude::*;
    use x509_parser::certificate::X509Certificate;

    const OLD_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
    const OLD_LABEL: &str = "COMPSIG-MLDSA44-Ed25519-SHA512";

    fn compute_old_m_prime(message: &[u8], context: &[u8]) -> Vec<u8> {
        let ph_m = Sha512::digest(message);

        let mut m_prime = Vec::with_capacity(
            OLD_PREFIX.len() + OLD_LABEL.len() + 1 + context.len() + ph_m.len(),
        );
        m_prime.extend_from_slice(OLD_PREFIX);
        m_prime.extend_from_slice(OLD_LABEL.as_bytes());
        m_prime.push(context.len() as u8);
        m_prime.extend_from_slice(context);
        m_prime.extend_from_slice(&ph_m);
        m_prime
    }

    fn verify_legacy_draft09(
        vk: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
        context: &[u8],
    ) -> Result<(), CompositeError> {
        if context.len() > 255 {
            return Err(CompositeError::InvalidContextLength);
        }

        let m_prime = compute_old_m_prime(message, context);

        // ML-DSA verification with old label as context
        ml_dsa_verify(&vk.vk_ml, &m_prime, OLD_LABEL.as_bytes(), &signature.sig_ml)
            .map_err(|_| CompositeError::InvalidMlDsaSignature)?;

        // Ed25519 signs M' directly (not pre-hashed)
        vk.vk_ed
            .verify(&m_prime, &signature.sig_ed)
            .map_err(|_| CompositeError::InvalidEdSignature)?;

        Ok(())
    }

    #[test]
    fn verify_old_r5_mldsa44_ed25519_certificate() {
        // CHANGE THIS PATH to point to your extracted cert
        let cert_path = "certs/id-MLDSA44-Ed25519-SHA512-1.3.6.1.5.5.7.6.39_ta.der";

        let cert_der = std::fs::read(cert_path)
            .expect("Failed to read old r5 certificate file");

        let (_, cert) = X509Certificate::from_der(&cert_der)
            .expect("Failed to parse X.509 DER certificate");

        // Get raw TBS bytes
        let tbs_bytes = cert.tbs_certificate.raw;

        // Get raw signature value
        let signature_bytes = cert.signature_value.data;

        // Extract raw concatenated public key from SPKI
        let spki_bytes = cert.tbs_certificate.subject_pki.subject_public_key.raw;

        // Parse composite key and signature
        let vk = VerifyingKey::try_from(spki_bytes)
            .expect("Failed to parse composite public key from old cert");

        let sig = Signature::try_from(signature_bytes)
            .expect("Failed to parse composite signature from old cert");

        // Verify using old draft-09 logic (context is empty for self-signed certs)
        verify_legacy_draft09(&vk, tbs_bytes, &sig, &[])
            .expect("Old draft-09 certificate FAILED to verify!");

        println!("✓ SUCCESS: Old r5 ML-DSA-44 + Ed25519 certificate verified correctly!");
    }
}