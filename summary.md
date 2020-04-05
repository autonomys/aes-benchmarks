## Security Analysis Summary

* Subspace Blockchain
* Proof-of-Replication
* Security Concerns
* AES & Intuition
* AES Internals (Algorithms)
* AES-NI
* GPUs
* FPGAs
* ASICs
* Conclusion

### The Subspace Ledger

The Subspace Ledger is a Nakamoto style blockchain protocol where the proof-of-work puzzle is replaced by a random audit of the archival history of the ledger. To add a new block, a farmer must prove that they are storing some past block. The more blocks a farmer stores, the more likely they are to win the block reward. Farmers may even store the entire blockchain multiple times to further increase their chances. This allows 'one-CPU-one-vote' to be become 'one-disk-one-vote'. 

To ensure that farmers truly are dedicating unique storage resources towards this task, they must store provably unique replicas of the blockchain. The task of replicating any individual block must consume some minimum amount of scarce resources so that w.h.p. no parallel attacker is able to create replicas on-demand, in response to an audit, faster than an honest farmer can broadcast their solution. At the same time, the process of filling a disk with replicas (plotting) must not be too time-consuming or energy intensive.

### Proofs of Replication

To ensure that each farmer stores a provably unique replica we need an invertible, deterministic function with random outputs, i.e. a pseudo-random-permutation (PRP). We can use any keyed PRP as long as we have a unique encoding key, such as the hash of the public key that the farmer uses as its reward address. 

To ensure that a farmer cannot encode on-demand, within the block time, we must make the encoding process inherently sequential. We do this by slicing the archival state in constant-sized 4096 byte pieces. Each piece is then encoded (individually) using the PRP in the Cipher Block Chaining (CBC) mode of operation. If we divide the piece into 16 byte blocks, then each of the resulting 256 block must be fully encoded by the PRP before we can begin encoding the next block. We may iteratively encode each block with the PRP in a depth-first manner for some number of iterations until we reach the desired encoding delay time.

The key question is the choice of PRP. We rule out SLOTH and Verifiable Delay Functions (VDFs) as it is well known that ASICs can provide a dramatic evaluation speedup. We also choose not to build a custom PRP, perhaps using a common hash function and a Feistel network, as rolling your own crypto is generally a bad idea. Instead we choose to use the most widely implemented, well studied, and efficiently optimized (in hardware) PRP in existence, the Advanced Encryption Standard (AES).

### Security Concerns

1. No parallel polynomial time attacker can encode in time less than a minimum encoding delay. If such an attacker existed they could mine a private chain faster than the honest network and easily double-spend.

2. The cost of trading time for space should be much higher than the cost of space, when considering the cost of energy. Even if an attacker could encode some solutions within the block time to gain an advantage, the cost would exceed the gain. How do we express this as a space time tradeoff?
 
3. Given custom designed ASICs for both the fast and slow attacker above, neither would be successful. The only rational way to participate in the network would be to honestly farm with disk space.

Space Time Tradeoffs -- In order to maintain the security of the protocol

ASIC Resistance -- In order to main the fairness of 'one-disk-one-vote'

### The Advanced Encryption Standard (AES)

AES is symmetric block cipher based on a substitution-permutation network that transforms a 16 byte plaintext (the state) into a 16 byte ciphertext over 10/12/14 rounds given a 16/24/32 byte secret key. 

For a proof-of-replication, we are not concerned with the secrecy of the data, as it is already publicly available and the encoding keys are also know. This allows us to utilize faster software and hardware implementations of AES that are otherwise susceptible to attacks that might leak information about the keys or plaintext. Instead we want to have tight lower bounds on the fastest anyone can encode with either existing or theoretical hardware. 

In order to achieve the desired encoding delay we iterate the AES cipher many times, feeding the resulting ciphertext back in as the plaintext, re-using the same key schedule. We can repeat this many times, as the output of each iteration is pseudo random and unique for a given initial input. We do this by iterating AES-128 (10 rounds / 11 keys), as it has the smallest key schedule, leading to more efficient parallel plotting with SIMD instructions and faster key expansion for verification. 

### AES Internals

The initial key is first expanded into an a schedule of 10/12/14 round keys.The initial key is then XORed with the state before applying the round functions. Each round consists of four operations. 

1) Substitute Bytes
2) Shift Rows
3) Mix Columns (skipped in the last round)
4) Add Round Key

Rounds are applied iteratively to the state. In the last round Mix Columns is omitted. Substitute bytes may be computed directly using Galois Fields Arithmetic or sped up using a pre-computed 256 byte S-Box. As a further optimization Substitute Bytes, Shift Rows and Mix Columns may be combined into a four larger 1 KB T-Tables. Each round then comprises 16x T-Table lookups, 16x XORs, and Add Round Key. 

Speed records

XMM Registers
Speed Records

All hardware implementations are derived from either the Look Up Table (LUT) or Bitslicing approach.

### AES-NI

AES was intended to be easy to implement in hardware and 

AES (in contrast to DES) was 

Pipelining 

Zen Architecture

VAES

### GPUs

CUDA and OpenCL

NVIDIA and AMD

LUT and Bitslicing 

Calculating theoretical potential 

### FPGAs (John)

### ASICs (John)

### Conclusion





