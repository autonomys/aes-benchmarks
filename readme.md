##  AES Speed Benchmarks

A collection of scripts, libraries, and notes on the performance across different AES / AES-NI / VAES / GPU implementations for different platforms, in order to correctly model the degree and speed of parallelism that an attacker can obtain for a given system.

### Machine Setup
```
# install curl, git, gcc (latest), build tools

$ sudo add-apt-repository ppa:ubuntu-toolchain-r/test
$ sudo apt update
$ sudo apt install git curl build-essential gcc-9
$ sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 60 --slave /usr/bin/g++ g++ /usr/bin/g++-9

# Install Rust
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Configure path
$ vim ~/.profile
$ export PATH="$HOME/.cargo/bin:$PATH"
$ source ~/.profile
$ source ~/.cargo/env

# Check installed
$ rustc --version

# Switch to nightly
$ rustup toolchain install nightly
$ rustup default nightly
$ rustc --version
r
```

### SSH Testing

#### Honest Node

```
ssh -i keys_rsa -p 22 subspace@subspacelabs.hopto.org
```

#### Zen2 Grinder Node

```
ssh -i keys_rsa -p 2222 subspace@subspacelabs.hopto.org
```

#### GPU Grinder Node

```
ssh -i keys_rsa -p 12345 ubuntu@176.122.88.128
```

#### Ice Lake Grinder Node

## Implementations to Test

For each Implementation describe:

* Summary 
* Minimum Number of Instructions
* Minimum Number of Cycles
* CPB by Architecture 
* Expected latency
* Expected throughput per core*

### Baseline Implementation in Software

Given 16 bytes of input data, organized into a 4x4 and an expanded encryption key forming R + 1 round keys, each 16 bytes. Iteratively apply R rounds.

Begin by XORing the first round key with the state (whitening).

For r - 1 rounds:

1. Substitute each byte with its corresponding S-Box Look-up-table (LUT) value. 
2. Shift each row per the cipher.
3. Mix each column per the cipher
4. XOR the resulting state with the round key.

For the final round, conduct steps 1, 2, and 4 above (skip mix columns).

Note that S-Box lookups are susceptible to side-channel attacks as they leak timing information that my be used to recover the secret key. As we are using a public encoding key these attacks are irrelevant.  

### T-Tables in Software

Steps 1, 2, and 3 above may be combined to form four 1 kb LUTs or T-Tables for encryption.

Begin by XORing the first round key with the state (whitening).

For r - 1 rounds:

1. For each column (4), for each byte one table lookup for each byte (4), XORing the resulting values together.
2. XOR the resulting state with the round key.

For the final round we still use the S-Box and Shift Rows from the from the previous implementation, followed by XOR with the final round key.

Note that all 16 Table lookups and all 16 XORs may be conducted in parallel for each round.

Note that T-Table lookups are susceptible to side-channel attacks as they leak timing information that my be used to recover the secret key. As we are using a public encoding key these attacks are irrelevant.

### Bit-slicing in Software

Bit-slicing leverages the SIMD instructions (AVX/2/512) native to modern x86 architectures to provide a performant alternative to LUTs that evaluates in constant time. Instead of operating on individual bytes of state, it operates on the Ith bit of as many different bytes that it can pack into existing XMM/YMM/ZMM SIMD registers as possible, in parallel. The underlying Galois field operations used to derive the S-Boxes and T-Tables are instead applied directly to each group of bits in parallel. 

Bit-slicing summary

Bit-slicing implementation can be faster than LUT given sufficient SIMD registers and the proper instructions, though they are more complex in code to fully utilize available parallelism.


### AES-NI w/Pipelining

Beginning with Westmere Architecture (circa 2010) and later with AMD Bulldozer (circa 2011) the steps required to preform one round of AES were implemented as instructions native to the processor that work in concert with the native SIMD architecture. The state and the round keys must be loaded into the native XMM/YMM/ZMM registers before calling the new instructions.

1. Begin by loading the state and all round keys into registers (1 cycle per operation).
2. XOR the first round key with the state (whitening) using the XOR instruction.
3. For r - 1 rounds, call the AES_ENC instruction on the state and rth round key.
4. For the final round, call AES_ENC_LAST on the state and final round key.




On modern architectures (Skylake/Zen), one round of AES encryption can be computed with a latency of four cycles and a throughput of 1 cycle. This allows calls to be pipelined to provide an effective throughput of 4x per core. The state and round keys must be loaded into the 

### VAES-NI w/ Pipelining

### GPU Accelerated T-Tables (CUDA)

### GPU Accelerated Bit-slicing (CUDA)

### GPU Accelerated T-Tables (OpenCL)

### GPU Accelerated Bit-slicing (OpenCL)

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

4. Optimized Implementation (This library)

Install and run benchmarks, all should run in roughly the same time (with no background processes) w/in < 1% variance.

```
    git clone https://github.com/subspace/aes-benchmarks.git
    cd aes-benchmarks
    cargo bench
```

* Encode single block with single key for R rounds storing key in register
* Encode single block with single key for R rounds storing key in memory
* Encode four blocks with single key for R rounds using a four stage pipeline storing keys in register
* Encode four blocks with single key for R rounds using a four stage pipeline storing keys in memory
* Encode single block with 24 keys for R/22 rounds (constant iterations) storing keys in registers
* Encode single block with 24 keys for R/22 rounds (constant iterations) storing keys in memory
* Encode four blocks in a pipeline with 24 keys for R/22 rounds storing keys in registers

Benchmarks show that all of the above will execute in the same time, showing that 

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


## VAES Commands Needed

```
VAES
__mm512i _mm512_aesenc_epi128 (__mm512i a, __mm512i RoundKey)
__mm512i _mm512_aesenclast_epi128 (__mm512i a, __mm512i RoundKey)
__mm512i _mm512_aesdec_epi128 (__mm512i a, __mm512i RoundKey)
__mm512i _mm512_aesdeclast_epi128 (__mm512i a, __mm512i RoundKey)

__mm512i _mm512_loadu_si512 (void const* mem_addr)
__mm512i _mm512_xor_si512(__mm512i a, __mm512i b)
void _mm512_storeu_si512 (void* mem_addr, __mm512i a)

_
```