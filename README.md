# Silent Threshold Encryption [ePrint:2024/263](https://eprint.iacr.org/2024/263)

Rust implementation of the silent-threshold encryption introduced in [ePrint:2024/263](https://eprint.iacr.org/2024/263). Benchmarks reported in the paper were run on a 2019 MacBook Pro with a 2.4 GHz Intel Core i9 processor. The library has been confirmed to work with version 1.76.0 of the Rust compiler. 

An end to end example is provided in the `examples/` directory.

## Dependencies
Install rust via:

```curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh```

## Benchmarking
The library can be built using ```cargo build --release```.

Use ```cargo bench``` to benchmark `setup` (KeyGen in the paper), `encryption`, and `decryption`. This is expected to take approximately 20 minutes. To run a specific benchmark, use ```cargo bench --bench <bench_name>```.

Use ```cargo run --example endtoend``` to check correctness of the implementation.

The results are saved in the `target/criterion` directory. A concise HTML report is generated in `target/criterion/index.html` and can be viewed on a browser (Google Chrome recommended).

If you wish to benchmark for a different set of parameters, you can modify the files in the `benches/` directory. 

## Unit Tests
Additionally, you can find individual unit tests at the end of the respective files in the `src/` directory. These can be run using ```cargo test <test_name>```. This will allow you to test the correctness of the implementation.

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Overview
* [`src/setup`](src/setup.rs): Contains an implementation for sampling public key pairs and aggregating keys of a chosen committee. Also contains the `partial_decryption` method which is essentially a BLS signature. Note that the `get_pk` method runs in quadratic time. This can be reduced to linear time by preprocessing commitments to lagrange polynomials.
* [`src/encryption`](src/encryption.rs): Contains an implementation of the `encrypt` method for the silent threshold encryption scheme.
* [`src/decryption`](src/decryption.rs): Contains an implementation of `agg_dec` which gathers partial decryptions and recovers the message.

## License
This library is released under the MIT License.

"Error handling philosophy" for crypto libs
- avoid specific errors that can lead to side channel attacks or leak any important information
  - e.g. when handling key material
  - to do this: a general approach is to mask results and return an opaque error at the end
    - for testing, we can have features gates that allow us to verify internals
- don't 'fail fast' always, only when validating public input.

Error handling and unwrap?
[x] utils.rs
[x] crs.rs
[x] setup.rs
[ ] aggregate.rs
[x] encryption.rs
[ ] decryption.rs
[ ] main.rs

TODOs

- add zeroize
- use proptest 
- we should look into using DudeCT for constant time verification checking
- also looking into failure masking patterns
- added thiserror!
  - will use this to reprop errors when appropriate instead of redefining them
  - 
### **Level 1: Traditional Unit Tests** ✅
- Basic functionality, edge cases, error conditions
- **Limitation**: Only tests specific inputs you think of

### **Level 2: Property-Based Testing** 🎯 (High ROI)
Property-testing frameworks like Bolero make it easy to test Rust code with multiple fuzzing engines and apply multiple testing methods to the same harness. This tests:
- Invariants that should hold for ALL valid inputs
- Probabilistic properties (e.g., "encryption should be randomized")
- Mathematical properties specific to your cryptographic scheme

### **Level 3: Fuzzing** 🔍 (Critical for crypto)
Fuzzing tests cryptographic authentication and feeds random inputs to find unexpected bugs, commonly used for security-sensitive software. This finds:
- Crashes, panics, memory safety issues
- Edge cases you didn't consider
- Side-channel vulnerabilities

### **Level 4: Constant-Time Verification** ⚡ (Essential)
Your use of `subtle` is great, but you also need:
- Timing-based tests to verify constant-time properties
- Tools like `dudect` or specialized timing analysis
- Statistical analysis of execution times

### **Level 5: Formal Verification** 🏆 (Gold standard)
NIST is exploring formal methods within cryptographic certification programs, and Microsoft is rewriting SymCrypt in Rust to enable formal verification while defending against side-channel attacks. Tools like:
- **Kani**: Proves properties about ALL possible executions
- **CBMC**: Model checking for C/Rust
- **Mathematical proofs**: External verification of cryptographic correctness

## Immediate Next Steps

1. **Add property-based tests** using `proptest` or `quickcheck` - high impact, relatively easy
2. **Set up fuzzing** with `cargo-fuzz` - critical for finding edge cases
3. **Implement timing tests** to validate your `subtle` usage works
4. **Consider Kani integration** for memory safety proofs

## Why This Matters

Machine-assisted proofs of cryptographic primitives like AES-256-GCM verify that implementations are memory safe and functionally correct. For a threshold encryption scheme, you need confidence that:
- No secret information leaks through timing
- All mathematical properties hold
- Implementation matches the cryptographic specification
- No edge cases cause vulnerabilities

The artifact above gives you a concrete roadmap from where you are now to production-ready cryptographic code with formal guarantees!