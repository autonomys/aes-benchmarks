##  AES Speed Benchmarks


* Compare Purism laptop (AES-NI) to Dell laptop (VAES-NI)
* Iteratively progress through different variants of AES
* For each mode compare both AES-128 and AES-256
* Test both CTR and CBC mode to see how many registers are used
* Add all results to google sheets tracker
* Need to setup debugger so that you can inspect the memory (if not expected)

1. OpenSSL

This test the standards implementation of AES using OpenSSL, which will use AES-NI by default. This will be limited to 16x XMM registers at 16 bytes each, though only one register will used in CBC mode. AES-NI can be manually disabled to see the pure software speed.

```
    # AES-128-CBC with AES-NI disabled
    OPENSSL_ia32cap="~0x200000200000000" openssl speed -elapsed -evp aes-128-cbc

    # AES-128-CBC with AES-NI enabled
	openssl speed -elapsed -evp aes-128-cbc

    # AES-256-CBC with AES-NI disabled
    OPENSSL_ia32cap="~0x200000200000000" openssl speed -elapsed -evp aes-256-cbc

    # AES-256-CBC with AES-NI enabled
	openssl speed -elapsed -evp aes-256-cbc
```

2. Rust AES crate at 1x and 8x blocks

This is a pure rust implementation of AES that also uses AES-NI by default. It can run in single block per instruction or eight blocks per instruction mode.

```
    git clone https://github.com/RustCrypto/block-ciphers.git
    cd block-ciphers
    cargo bench
```

3. Rust crypto-primitives 

This is rust bindings to C code that can take advantage of AVX-512 registers and VAES instructions.
Ensure gcc or clang are updated to latest version, else it will not build!
If you don't have Ice Lake architecture only the first half of benchmarks will run.

```
    git clone https://github.com/elalfer/rust-crypto-pimitives.git
    cd rust-crypto-pimitives
    cargo bench
```

4. Optimized Implementation

Overview

1. Start with single round encode / decode
2. Attempt optimized throughput encode / decode on XMM (15)
3. Iterate on the number of rounds
4. Add in a block cipher
5. Implement parallel decryption
6. Implement the opposite for attacker

Use Nazar's variable block width code as a guide.
Start with a simple function
  * bring in the right libraries
  * set the compile instructions correctly
  * given a 16 byte key and 16 byte plaintext block
  * compute one round of rijndael using AES-NI
  * return the ciphertext
  * compute the inverse
  * verify they match


## Use of AES Instruction Set

### Constraints

1. Number of registers (16 or 32)
2. Width of registers (16, 32, or 64 bytes)
3. Instructions (AES, VAES)
4. Latency of Instructions (for pipelining)

## Implementations

1. Traditional AES-256-CBC encoding with constant keys
2. Subspace Optimized AES-256 encoding
3. Optimize pipelining to improve effective throughput (4, 5, 6x ???)
4. Widen registers for VAES/AVX-512
5. How to take advantage of AMD Zen?
6. Introduce concurrency with multiple cores
7. Write optimized CBC decoding function (why 8x speedup before?)
8. Write batched encoder to test sustained effective plotting throughput and bench
9.  Rewrite encoder as the parallel attacker (invert)
10. Benchmark the fast attacker (how fast can he extend a private chain)
11. Benchmark the slow attacker with VAES/AVX-512 (how much advantage can he gain?)

## Key Questions

1. Confirm that pipelining actually works the way you expect -- it does!
   1. Confirm it works the same on Ice Lake and Purism machines
2. Why do we then see a higher speed on decryption with decode eight? -- You don't!
3. How do you take advantage of AMD Zen 2x AES-NI? -- not clear at all
4. How do you actually employ VAES w/ZMM -- we can test this
   1. Write same code for VAES
   2. Extend to handle several pieces in parallel 


## Design

1. Optimal plotting algo (mainly key schedule)
2. Optimal attacker algo


## Testing Results

1. SW Only -- what is the best implementation (ignoring cache timing attacks)
2. AES-NI -- what is the best pipelining achievable? 4x at 1/4 SW only speed
3. VAES -- what is the best vectorization achievable? AES NI + 4x at 1/4 SW only speed
4. GPU -- what is the best parallelism achievable? 4000x at 4x SW only speed