#![allow(dead_code)]
use core::arch::x86_64::*;
use rand::Rng;
// use unroll::*;

/// Generate a array of random bytes of length 16 to be used as a sample block.
pub fn random_bytes_16() -> [u8; 16] {
  let mut bytes = [0u8; 16];
  rand::thread_rng().fill(&mut bytes[..]);
  bytes
}

/// Generate a array of random bytes of length 176 to be used as a flat key.
pub fn random_bytes_176() -> [u8; 176] {
  let mut bytes = [0u8; 176];
  rand::thread_rng().fill(&mut bytes[..]);
  bytes
}

/// Generate a array of random bytes of length 176 to be used as a flat key.
pub fn random_bytes_64() -> [u8; 64] {
  let mut bytes = [0u8; 64];
  rand::thread_rng().fill(&mut bytes[..]);
  bytes
}

/// Generate a array of random bytes of length 176 to be used as a flat key.
pub fn random_bytes_192() -> [u8; 192] {
  let mut bytes = [0u8; 192];
  rand::thread_rng().fill(&mut bytes[..]);
  bytes
}

#[inline(always)]
// #[unroll_for_loops()]
pub unsafe fn encode_aes_ni_128(
  keys: &[[u8; 16]; 11],
  plaintext: &[u8; 16],
  rounds: usize,
) -> [u8; 16] {

  // load plaintext data from memory into a single xmm register
  let mut pt_register = _mm_loadu_si128(plaintext.as_ptr() as *const __m128i);

  // load keys from memory into a 11 xmm registers
  let key_0_register = _mm_loadu_si128(keys[0].as_ptr() as *const __m128i);
  let key_1_register = _mm_loadu_si128(keys[1].as_ptr() as *const __m128i);
  let key_2_register = _mm_loadu_si128(keys[2].as_ptr() as *const __m128i);
  let key_3_register = _mm_loadu_si128(keys[3].as_ptr() as *const __m128i);
  let key_4_register = _mm_loadu_si128(keys[4].as_ptr() as *const __m128i);
  let key_5_register = _mm_loadu_si128(keys[5].as_ptr() as *const __m128i);
  let key_6_register = _mm_loadu_si128(keys[6].as_ptr() as *const __m128i);
  let key_7_register = _mm_loadu_si128(keys[7].as_ptr() as *const __m128i);
  let key_8_register = _mm_loadu_si128(keys[8].as_ptr() as *const __m128i);
  let key_9_register = _mm_loadu_si128(keys[9].as_ptr() as *const __m128i);
  let key_10_register = _mm_loadu_si128(keys[10].as_ptr() as *const __m128i);

  for _ in 0..rounds {
    // xor the input with first key (whitening)
    pt_register = _mm_xor_si128(pt_register, key_0_register);

    // call nine rounds of Rijndael using AES-NI with each key
    pt_register = _mm_aesenc_si128(pt_register, key_1_register);
    pt_register = _mm_aesenc_si128(pt_register, key_2_register);
    pt_register = _mm_aesenc_si128(pt_register, key_3_register);
    pt_register = _mm_aesenc_si128(pt_register, key_4_register);
    pt_register = _mm_aesenc_si128(pt_register, key_5_register);
    pt_register = _mm_aesenc_si128(pt_register, key_6_register);
    pt_register = _mm_aesenc_si128(pt_register, key_7_register);
    pt_register = _mm_aesenc_si128(pt_register, key_8_register);
    pt_register = _mm_aesenc_si128(pt_register, key_9_register);

    // perform final round of AES
    pt_register = _mm_aesenclast_si128(pt_register, key_10_register);

  }

  // init memory for ciphertext
  let mut ciphertext = [0u8; 16];

  // store ciphertext back into memory and return
  _mm_storeu_si128(ciphertext.as_mut_ptr() as *mut __m128i, pt_register);

  // return ciphertext
  ciphertext
}

#[inline(always)]
pub unsafe fn decode_aes_ni_128(
  keys: &[[u8; 16]; 11],
  ciphertext: &[u8; 16],
  rounds: usize,
) -> [u8; 16] {

  // load plaintext data from memory into a single xmm register
  let mut ct_register = _mm_loadu_si128(ciphertext.as_ptr() as *const __m128i);

  // load each key from memory into a 11 xmm registers
  // then invert each of the keys for decryption

  let key_0_register = _mm_loadu_si128(keys[0].as_ptr() as *const __m128i);

  let key_1_register = _mm_loadu_si128(keys[1].as_ptr() as *const __m128i);
  let inv_key_1_register =_mm_aesimc_si128(key_1_register);

  let key_2_register = _mm_loadu_si128(keys[2].as_ptr() as *const __m128i);
  let inv_key_2_register =_mm_aesimc_si128(key_2_register);

  let key_3_register = _mm_loadu_si128(keys[3].as_ptr() as *const __m128i);
  let inv_key_3_register =_mm_aesimc_si128(key_3_register);

  let key_4_register = _mm_loadu_si128(keys[4].as_ptr() as *const __m128i);
  let inv_key_4_register =_mm_aesimc_si128(key_4_register);

  let key_5_register = _mm_loadu_si128(keys[5].as_ptr() as *const __m128i);
  let inv_key_5_register =_mm_aesimc_si128(key_5_register);

  let key_6_register = _mm_loadu_si128(keys[6].as_ptr() as *const __m128i);
  let inv_key_6_register =_mm_aesimc_si128(key_6_register);

  let key_7_register = _mm_loadu_si128(keys[7].as_ptr() as *const __m128i);
  let inv_key_7_register =_mm_aesimc_si128(key_7_register);

  let key_8_register = _mm_loadu_si128(keys[8].as_ptr() as *const __m128i);
  let inv_key_8_register =_mm_aesimc_si128(key_8_register);

  let key_9_register = _mm_loadu_si128(keys[9].as_ptr() as *const __m128i);
  let inv_key_9_register =_mm_aesimc_si128(key_9_register);

  let key_10_register = _mm_loadu_si128(keys[10].as_ptr() as *const __m128i);

  for _ in 0..rounds {
    // xor the input with last key (whitening)
    ct_register = _mm_xor_si128(ct_register, key_10_register);

    // call nine rounds of Rijndael using AES-NI with each inverse key
    ct_register = _mm_aesdec_si128(ct_register, inv_key_9_register);
    ct_register = _mm_aesdec_si128(ct_register, inv_key_8_register);
    ct_register = _mm_aesdec_si128(ct_register, inv_key_7_register);
    ct_register = _mm_aesdec_si128(ct_register, inv_key_6_register);
    ct_register = _mm_aesdec_si128(ct_register, inv_key_5_register);
    ct_register = _mm_aesdec_si128(ct_register, inv_key_4_register);
    ct_register = _mm_aesdec_si128(ct_register, inv_key_3_register);
    ct_register = _mm_aesdec_si128(ct_register, inv_key_2_register);
    ct_register = _mm_aesdec_si128(ct_register, inv_key_1_register);

    // encode final round with first key
    ct_register = _mm_aesdeclast_si128(ct_register, key_0_register);
  }

  // init memory for ciphertext
  let mut plaintext = [0u8; 16];

  // store ciphertext back into memory and return
  _mm_storeu_si128(plaintext.as_mut_ptr() as *mut __m128i, ct_register);

  // return ciphertext
  plaintext
}

#[inline(always)]
pub unsafe fn encode_aes_ni_128_pipelined_x4(
  keys: &[[u8; 16]; 11],
  plaintexts: &[[u8; 16]; 4],
  rounds: usize,
) -> [[u8; 16]; 4] {

  // load plaintext data from memory for each block into four xmm registers
  let mut pt_0_register = _mm_loadu_si128(plaintexts[0].as_ptr() as *const __m128i);
  let mut pt_1_register = _mm_loadu_si128(plaintexts[1].as_ptr() as *const __m128i);
  let mut pt_2_register = _mm_loadu_si128(plaintexts[2].as_ptr() as *const __m128i);
  let mut pt_3_register = _mm_loadu_si128(plaintexts[3].as_ptr() as *const __m128i);

  // load keys from memory into 11 xmm registers
  let key_0_register = _mm_loadu_si128(keys[0].as_ptr() as *const __m128i);
  let key_1_register = _mm_loadu_si128(keys[1].as_ptr() as *const __m128i);
  let key_2_register = _mm_loadu_si128(keys[2].as_ptr() as *const __m128i);
  let key_3_register = _mm_loadu_si128(keys[3].as_ptr() as *const __m128i);
  let key_4_register = _mm_loadu_si128(keys[4].as_ptr() as *const __m128i);
  let key_5_register = _mm_loadu_si128(keys[5].as_ptr() as *const __m128i);
  let key_6_register = _mm_loadu_si128(keys[6].as_ptr() as *const __m128i);
  let key_7_register = _mm_loadu_si128(keys[7].as_ptr() as *const __m128i);
  let key_8_register = _mm_loadu_si128(keys[8].as_ptr() as *const __m128i);
  let key_9_register = _mm_loadu_si128(keys[9].as_ptr() as *const __m128i);
  let key_10_register = _mm_loadu_si128(keys[10].as_ptr() as *const __m128i);

  for _ in 0..rounds {
    // xor the input of each block with first key (whitening)
    pt_0_register = _mm_xor_si128(pt_0_register, key_0_register);
    pt_1_register = _mm_xor_si128(pt_1_register, key_0_register);
    pt_2_register = _mm_xor_si128(pt_2_register, key_0_register);
    pt_3_register = _mm_xor_si128(pt_3_register, key_0_register);

    // call nine rounds of Rijndael using AES-NI with each key
    pt_0_register = _mm_aesenc_si128(pt_0_register, key_1_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_1_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_1_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_1_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_2_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_2_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_2_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_2_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_3_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_3_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_3_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_3_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_4_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_4_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_4_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_4_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_5_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_5_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_5_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_5_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_6_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_6_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_6_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_6_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_7_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_7_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_7_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_7_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_8_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_8_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_8_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_8_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_9_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_9_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_9_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_9_register);

    // encode final round with last key
    pt_0_register = _mm_aesenclast_si128(pt_0_register, key_10_register);
    pt_1_register = _mm_aesenclast_si128(pt_1_register, key_10_register);
    pt_2_register = _mm_aesenclast_si128(pt_2_register, key_10_register);
    pt_3_register = _mm_aesenclast_si128(pt_3_register, key_10_register);
  }

  // init memory for ciphertext
  let mut ciphertext_0 = [0u8; 16];
  let mut ciphertext_1 = [0u8; 16];
  let mut ciphertext_2 = [0u8; 16];
  let mut ciphertext_3 = [0u8; 16];

  // store ciphertext back into memory and return
  _mm_storeu_si128(ciphertext_0.as_mut_ptr() as *mut __m128i, pt_0_register);
  _mm_storeu_si128(ciphertext_1.as_mut_ptr() as *mut __m128i, pt_1_register);
  _mm_storeu_si128(ciphertext_2.as_mut_ptr() as *mut __m128i, pt_2_register);
  _mm_storeu_si128(ciphertext_3.as_mut_ptr() as *mut __m128i, pt_3_register);

  // return ciphertext
  [
    ciphertext_0,
    ciphertext_1,
    ciphertext_2,
    ciphertext_3,
  ]
}

#[inline(always)]
pub unsafe fn encode_aes_ni_128_pipelined_x8(
  keys: &[[u8; 16]; 11],
  plaintexts: &[[u8; 16]; 8],
  rounds: usize,
) -> [[u8; 16]; 8] {

  // load plaintext data from memory for each block into four xmm registers
  let mut pt_0_register = _mm_loadu_si128(plaintexts[0].as_ptr() as *const __m128i);
  let mut pt_1_register = _mm_loadu_si128(plaintexts[1].as_ptr() as *const __m128i);
  let mut pt_2_register = _mm_loadu_si128(plaintexts[2].as_ptr() as *const __m128i);
  let mut pt_3_register = _mm_loadu_si128(plaintexts[3].as_ptr() as *const __m128i);
  let mut pt_4_register = _mm_loadu_si128(plaintexts[4].as_ptr() as *const __m128i);
  let mut pt_5_register = _mm_loadu_si128(plaintexts[5].as_ptr() as *const __m128i);
  let mut pt_6_register = _mm_loadu_si128(plaintexts[6].as_ptr() as *const __m128i);
  let mut pt_7_register = _mm_loadu_si128(plaintexts[7].as_ptr() as *const __m128i);

  // load keys from memory into 11 xmm registers
  let key_0_register = _mm_loadu_si128(keys[0].as_ptr() as *const __m128i);
  let key_1_register = _mm_loadu_si128(keys[1].as_ptr() as *const __m128i);
  let key_2_register = _mm_loadu_si128(keys[2].as_ptr() as *const __m128i);
  let key_3_register = _mm_loadu_si128(keys[3].as_ptr() as *const __m128i);
  let key_4_register = _mm_loadu_si128(keys[4].as_ptr() as *const __m128i);
  let key_5_register = _mm_loadu_si128(keys[5].as_ptr() as *const __m128i);
  let key_6_register = _mm_loadu_si128(keys[6].as_ptr() as *const __m128i);
  let key_7_register = _mm_loadu_si128(keys[7].as_ptr() as *const __m128i);
  let key_8_register = _mm_loadu_si128(keys[8].as_ptr() as *const __m128i);
  let key_9_register = _mm_loadu_si128(keys[9].as_ptr() as *const __m128i);
  let key_10_register = _mm_loadu_si128(keys[10].as_ptr() as *const __m128i);

  for _ in 0..rounds {
    // xor the input of each block with first key (whitening)
    pt_0_register = _mm_xor_si128(pt_0_register, key_0_register);
    pt_1_register = _mm_xor_si128(pt_1_register, key_0_register);
    pt_2_register = _mm_xor_si128(pt_2_register, key_0_register);
    pt_3_register = _mm_xor_si128(pt_3_register, key_0_register);
    pt_4_register = _mm_xor_si128(pt_4_register, key_0_register);
    pt_5_register = _mm_xor_si128(pt_5_register, key_0_register);
    pt_6_register = _mm_xor_si128(pt_6_register, key_0_register);
    pt_7_register = _mm_xor_si128(pt_7_register, key_0_register);

    // call nine rounds of Rijndael using AES-NI with each key
    pt_0_register = _mm_aesenc_si128(pt_0_register, key_1_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_1_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_1_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_1_register);
    pt_4_register = _mm_aesenc_si128(pt_4_register, key_1_register);
    pt_5_register = _mm_aesenc_si128(pt_5_register, key_1_register);
    pt_6_register = _mm_aesenc_si128(pt_6_register, key_1_register);
    pt_7_register = _mm_aesenc_si128(pt_7_register, key_1_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_2_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_2_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_2_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_2_register);
    pt_4_register = _mm_aesenc_si128(pt_4_register, key_2_register);
    pt_5_register = _mm_aesenc_si128(pt_5_register, key_2_register);
    pt_6_register = _mm_aesenc_si128(pt_6_register, key_2_register);
    pt_7_register = _mm_aesenc_si128(pt_7_register, key_2_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_3_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_3_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_3_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_3_register);
    pt_4_register = _mm_aesenc_si128(pt_4_register, key_3_register);
    pt_5_register = _mm_aesenc_si128(pt_5_register, key_3_register);
    pt_6_register = _mm_aesenc_si128(pt_6_register, key_3_register);
    pt_7_register = _mm_aesenc_si128(pt_7_register, key_3_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_4_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_4_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_4_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_4_register);
    pt_4_register = _mm_aesenc_si128(pt_4_register, key_4_register);
    pt_5_register = _mm_aesenc_si128(pt_5_register, key_4_register);
    pt_6_register = _mm_aesenc_si128(pt_6_register, key_4_register);
    pt_7_register = _mm_aesenc_si128(pt_7_register, key_4_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_5_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_5_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_5_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_5_register);
    pt_4_register = _mm_aesenc_si128(pt_4_register, key_5_register);
    pt_5_register = _mm_aesenc_si128(pt_5_register, key_5_register);
    pt_6_register = _mm_aesenc_si128(pt_6_register, key_5_register);
    pt_7_register = _mm_aesenc_si128(pt_7_register, key_5_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_6_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_6_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_6_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_6_register);
    pt_4_register = _mm_aesenc_si128(pt_4_register, key_6_register);
    pt_5_register = _mm_aesenc_si128(pt_5_register, key_6_register);
    pt_6_register = _mm_aesenc_si128(pt_6_register, key_6_register);
    pt_7_register = _mm_aesenc_si128(pt_7_register, key_6_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_7_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_7_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_7_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_7_register);
    pt_4_register = _mm_aesenc_si128(pt_4_register, key_7_register);
    pt_5_register = _mm_aesenc_si128(pt_5_register, key_7_register);
    pt_6_register = _mm_aesenc_si128(pt_6_register, key_7_register);
    pt_7_register = _mm_aesenc_si128(pt_7_register, key_7_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_8_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_8_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_8_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_8_register);
    pt_4_register = _mm_aesenc_si128(pt_4_register, key_8_register);
    pt_5_register = _mm_aesenc_si128(pt_5_register, key_8_register);
    pt_6_register = _mm_aesenc_si128(pt_6_register, key_8_register);
    pt_7_register = _mm_aesenc_si128(pt_7_register, key_8_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_9_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_9_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_9_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_9_register);
    pt_4_register = _mm_aesenc_si128(pt_4_register, key_9_register);
    pt_5_register = _mm_aesenc_si128(pt_5_register, key_9_register);
    pt_6_register = _mm_aesenc_si128(pt_6_register, key_9_register);
    pt_7_register = _mm_aesenc_si128(pt_7_register, key_9_register);

    // encode final round with last key
    pt_0_register = _mm_aesenclast_si128(pt_0_register, key_10_register);
    pt_1_register = _mm_aesenclast_si128(pt_1_register, key_10_register);
    pt_2_register = _mm_aesenclast_si128(pt_2_register, key_10_register);
    pt_3_register = _mm_aesenclast_si128(pt_3_register, key_10_register);
    pt_4_register = _mm_aesenclast_si128(pt_4_register, key_10_register);
    pt_5_register = _mm_aesenclast_si128(pt_5_register, key_10_register);
    pt_6_register = _mm_aesenclast_si128(pt_6_register, key_10_register);
    pt_7_register = _mm_aesenclast_si128(pt_7_register, key_10_register);
  }

  // init memory for ciphertexts
  let mut ciphertext_0 = [0u8; 16];
  let mut ciphertext_1 = [0u8; 16];
  let mut ciphertext_2 = [0u8; 16];
  let mut ciphertext_3 = [0u8; 16];
  let mut ciphertext_4 = [0u8; 16];
  let mut ciphertext_5 = [0u8; 16];
  let mut ciphertext_6 = [0u8; 16];
  let mut ciphertext_7 = [0u8; 16];

  // store ciphertexts back into memory and return
  _mm_storeu_si128(ciphertext_0.as_mut_ptr() as *mut __m128i, pt_0_register);
  _mm_storeu_si128(ciphertext_1.as_mut_ptr() as *mut __m128i, pt_1_register);
  _mm_storeu_si128(ciphertext_2.as_mut_ptr() as *mut __m128i, pt_2_register);
  _mm_storeu_si128(ciphertext_3.as_mut_ptr() as *mut __m128i, pt_3_register);
  _mm_storeu_si128(ciphertext_4.as_mut_ptr() as *mut __m128i, pt_4_register);
  _mm_storeu_si128(ciphertext_5.as_mut_ptr() as *mut __m128i, pt_5_register);
  _mm_storeu_si128(ciphertext_6.as_mut_ptr() as *mut __m128i, pt_6_register);
  _mm_storeu_si128(ciphertext_7.as_mut_ptr() as *mut __m128i, pt_7_register);

  // return ciphertexts
  [
    ciphertext_0,
    ciphertext_1,
    ciphertext_2,
    ciphertext_3,
    ciphertext_4,
    ciphertext_5,
    ciphertext_6,
    ciphertext_7,
  ]
}

#[inline(always)]
pub unsafe fn encode_aes_ni_c_128(
  keys: &[u8; 176],
  plaintext: &[u8; 16],
  rounds: usize,
) -> [u8; 16] {
  let mut output = [0u8; 16];
  aesni_enc_block(plaintext.as_ptr(), keys.as_ptr(), rounds, output.as_mut_ptr());
  output
}

#[inline(always)]
pub unsafe fn encode_vaes_ni_c_512(
  keys: &[u8; 176],
  plaintext: &[u8; 64],
  rounds: usize,
) -> [u8; 64] {
  let mut output = [0u8; 64];
  vaesni_enc_block(plaintext.as_ptr(), keys.as_ptr(), rounds, output.as_mut_ptr());
  output
}

#[inline(always)]
pub unsafe fn encode_vaes_ni_c_512_x3(
  keys: &[u8; 176],
  plaintext: &[u8; 192],
  rounds: usize,
) -> [[u8; 64]; 3] {
  let mut output_0 = [0u8; 64];
  let mut output_1 = [0u8; 64];
  let mut output_2 = [0u8; 64];
  vaesni_enc_block_x3(plaintext.as_ptr(), keys.as_ptr(), rounds, output_0.as_mut_ptr(), output_1.as_mut_ptr(), output_2.as_mut_ptr());
  [output_0, output_1, output_2]
}

// Import C implementations
#[link(name = "vaes_c.a")]
extern "C" {
    fn aesni_enc_block(input: *const u8, key: *const u8, rounds: usize, output: *mut u8);

    fn vaesni_enc_block(input: *const u8, key: *const u8, rounds: usize, output: *mut u8);

    fn vaesni_enc_block_x3(input: *const u8, key: *const u8, rounds: usize, output_0: *mut u8, output_1: *mut u8, output_2: *mut u8);
}
