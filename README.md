# pq-xwing-sig

**⚠️ WARNING: This crate is under active development and is not suitable for production use. It may contain security vulnerabilities. Use at your own risk.**

Post-quantum composite signature (ML-DSA variants + Ed25519/Ed448).

This crate attempts to implement the composite signature as described in the [Composite ML-DSA for use in X.509 Public Key Infrastructure](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/).

**Current status (v0.1.0)**:  
Active development in progress. Functional proof-of-concept implementation exists, but it is **not yet security-hardened** (constant-time guarantees, full fuzzing, formal verification, or external audit pending).

**Do not use in production yet.**

- **Implemented variants**: ML-DSA-44 + Ed25519, ML-DSA-65 + Ed25519, ML-DSA-87 + Ed448 (per draft-ietf-lamps-pq-composite-sigs-13).
- **Constant-time notes**: Partial constant-time operations (e.g., `ct_eq` for key/signature equality). Full guarantees pending.
- **Quick build**: Requires Rust 1.70+; run `cargo build` from the root. Test with `cargo test` (but expect incomplete coverage).

Planned improvements:
- Full constant-time operations
- Extensive testing and fuzzing
- Benchmarks and documentation
- no-std support

See the repository for ongoing work: https://github.com/Slurp9187/pq-composite-sig
