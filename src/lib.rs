#![allow(dead_code)]
use core::arch::x86_64::*;
use rand::Rng;

#[inline(always)]
pub unsafe fn encode(
  key: [u8; 16], 
  plaintext: [u8; 16],
  rounds: usize,
) -> [u8; 16] {

  // load plaintext data from memory into a single xmm register
  let mut pt_register = _mm_loadu_si128(plaintext.as_ptr() as *const __m128i);
  
  // load key from memory into a single xmm register
  let key_register = _mm_loadu_si128(key.as_ptr() as *const __m128i);

  // xor the input with key
  pt_register = _mm_xor_si128(pt_register, key_register);

  // call r-1  round of Rijndael using AES-NI with same key for now
  for _ in 1..rounds {
    pt_register = _mm_aesenc_si128(pt_register, key_register);
  }
  
  // encode final round
  pt_register = _mm_aesenclast_si128(pt_register, key_register);
  
  // init memory for ciphertext
  let mut ciphertext = [0u8; 16];

  // store ciphertext back into memory and return
  _mm_storeu_si128(ciphertext.as_mut_ptr() as *mut __m128i, pt_register);

  // return ciphertext
  ciphertext
}

#[inline(always)]
pub unsafe fn encode_memory(
  key: [u8; 16], 
  plaintext: [u8; 16],
  rounds: usize,
) -> [u8; 16] {

  // load plaintext data from memory into a single xmm register
  let mut pt_register = _mm_loadu_si128(plaintext.as_ptr() as *const __m128i);
  
  // load key from memory into a single xmm register
  let key_memory = key.as_ptr() as *const __m128i;

  // xor the input with key
  pt_register = _mm_xor_si128(pt_register, *key_memory);

  // call r-1  round of Rijndael using AES-NI with same key for now
  for _ in 1..rounds {
    pt_register = _mm_aesenc_si128(pt_register, *key_memory);
  }
  
  // encode final round
  pt_register = _mm_aesenclast_si128(pt_register, *key_memory);
  
  // init memory for ciphertext
  let mut ciphertext = [0u8; 16];

  // store ciphertext back into memory and return
  _mm_storeu_si128(ciphertext.as_mut_ptr() as *mut __m128i, pt_register);

  // return ciphertext
  ciphertext
}



#[inline(always)]
pub unsafe fn encode_with_keys(
  keys: [[u8; 16]; 96], 
  plaintext: [u8; 16],
  rounds: usize,
) -> [u8; 16] {

  // load plaintext data from memory into a single xmm register
  let mut pt_register = _mm_loadu_si128(plaintext.as_ptr() as *const __m128i);
  
  // load key from memory into a single xmm register
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
  let key_11_register = _mm_loadu_si128(keys[11].as_ptr() as *const __m128i);
  let key_12_register = _mm_loadu_si128(keys[12].as_ptr() as *const __m128i);
  let key_13_register = _mm_loadu_si128(keys[13].as_ptr() as *const __m128i);
  let key_14_register = _mm_loadu_si128(keys[14].as_ptr() as *const __m128i);
  let key_15_register = _mm_loadu_si128(keys[15].as_ptr() as *const __m128i);
  let key_16_register = _mm_loadu_si128(keys[16].as_ptr() as *const __m128i);
  let key_17_register = _mm_loadu_si128(keys[17].as_ptr() as *const __m128i);
  let key_18_register = _mm_loadu_si128(keys[18].as_ptr() as *const __m128i);
  let key_19_register = _mm_loadu_si128(keys[19].as_ptr() as *const __m128i);
  let key_20_register = _mm_loadu_si128(keys[20].as_ptr() as *const __m128i);
  let key_21_register = _mm_loadu_si128(keys[21].as_ptr() as *const __m128i);
  let key_22_register = _mm_loadu_si128(keys[22].as_ptr() as *const __m128i);
  let key_23_register = _mm_loadu_si128(keys[23].as_ptr() as *const __m128i);

  // xor the input with key
  pt_register = _mm_xor_si128(pt_register, key_0_register);

  // call r-1  round of Rijndael using AES-NI with same key for now
  for _ in 1..(rounds/22) {
    pt_register = _mm_aesenc_si128(pt_register, key_1_register);
    pt_register = _mm_aesenc_si128(pt_register, key_2_register);
    pt_register = _mm_aesenc_si128(pt_register, key_3_register);
    pt_register = _mm_aesenc_si128(pt_register, key_4_register);
    pt_register = _mm_aesenc_si128(pt_register, key_5_register);
    pt_register = _mm_aesenc_si128(pt_register, key_6_register);
    pt_register = _mm_aesenc_si128(pt_register, key_7_register);
    pt_register = _mm_aesenc_si128(pt_register, key_8_register);
    pt_register = _mm_aesenc_si128(pt_register, key_9_register);
    pt_register = _mm_aesenc_si128(pt_register, key_10_register);
    pt_register = _mm_aesenc_si128(pt_register, key_11_register);
    pt_register = _mm_aesenc_si128(pt_register, key_12_register);
    pt_register = _mm_aesenc_si128(pt_register, key_13_register);
    pt_register = _mm_aesenc_si128(pt_register, key_14_register);
    pt_register = _mm_aesenc_si128(pt_register, key_15_register);
    pt_register = _mm_aesenc_si128(pt_register, key_16_register);
    pt_register = _mm_aesenc_si128(pt_register, key_17_register);
    pt_register = _mm_aesenc_si128(pt_register, key_18_register);
    pt_register = _mm_aesenc_si128(pt_register, key_19_register);
    pt_register = _mm_aesenc_si128(pt_register, key_20_register);
    pt_register = _mm_aesenc_si128(pt_register, key_21_register);
    pt_register = _mm_aesenc_si128(pt_register, key_22_register);
  }
  
  // encode final round
  pt_register = _mm_aesenclast_si128(pt_register, key_23_register);
  
  // init memory for ciphertext
  let mut ciphertext = [0u8; 16];

  // store ciphertext back into memory and return
  _mm_storeu_si128(ciphertext.as_mut_ptr() as *mut __m128i, pt_register);

  // return ciphertext
  ciphertext
}

#[inline(always)]
pub unsafe fn encode_with_keys_memory(
  keys: [[u8; 16]; 96], 
  plaintext: [u8; 16],
  rounds: usize,
) -> [u8; 16] {

  // load plaintext data from memory into a single xmm register
  let mut pt_register = _mm_loadu_si128(plaintext.as_ptr() as *const __m128i);
  
  // load key from memory into a single xmm register
  let key_0_memory = keys[0].as_ptr() as *const __m128i;
  let key_1_memory = keys[1].as_ptr() as *const __m128i;
  let key_2_memory = keys[2].as_ptr() as *const __m128i;
  let key_3_memory = keys[3].as_ptr() as *const __m128i;
  let key_4_memory = keys[4].as_ptr() as *const __m128i;
  let key_5_memory = keys[5].as_ptr() as *const __m128i;
  let key_6_memory = keys[6].as_ptr() as *const __m128i;
  let key_7_memory = keys[7].as_ptr() as *const __m128i;
  let key_8_memory = keys[8].as_ptr() as *const __m128i;
  let key_9_memory = keys[9].as_ptr() as *const __m128i;
  let key_10_memory = keys[10].as_ptr() as *const __m128i;
  let key_11_memory = keys[11].as_ptr() as *const __m128i;
  let key_12_memory = keys[12].as_ptr() as *const __m128i;
  let key_13_memory = keys[13].as_ptr() as *const __m128i;
  let key_14_memory = keys[14].as_ptr() as *const __m128i;
  let key_15_memory = keys[15].as_ptr() as *const __m128i;
  let key_16_memory = keys[16].as_ptr() as *const __m128i;
  let key_17_memory = keys[17].as_ptr() as *const __m128i;
  let key_18_memory = keys[18].as_ptr() as *const __m128i;
  let key_19_memory = keys[19].as_ptr() as *const __m128i;
  let key_20_memory = keys[20].as_ptr() as *const __m128i;
  let key_21_memory = keys[21].as_ptr() as *const __m128i;
  let key_22_memory = keys[22].as_ptr() as *const __m128i;
  let key_23_memory = keys[23].as_ptr() as *const __m128i;

  // xor the input with key
  pt_register = _mm_xor_si128(pt_register, *key_0_memory);

  // call r-1  round of Rijndael using AES-NI with same key for now
  for _ in 1..(rounds/22) {
    pt_register = _mm_aesenc_si128(pt_register, *key_1_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_2_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_3_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_4_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_5_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_6_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_7_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_8_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_9_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_10_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_11_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_12_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_13_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_14_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_15_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_16_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_17_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_18_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_19_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_20_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_21_memory);
    pt_register = _mm_aesenc_si128(pt_register, *key_22_memory);
  }
  
  // encode final round
  pt_register = _mm_aesenclast_si128(pt_register, *key_23_memory);
  
  // init memory for ciphertext
  let mut ciphertext = [0u8; 16];

  // store ciphertext back into memory and return
  _mm_storeu_si128(ciphertext.as_mut_ptr() as *mut __m128i, pt_register);

  // return ciphertext
  ciphertext
}

#[inline(always)]
pub unsafe fn decode(
  key: [u8; 16], 
  ciphertext: [u8; 16],
  rounds: usize,
) -> [u8; 16] {

  // load ciphertext data from memory into a single xmm register
  let mut ct_register = _mm_loadu_si128(ciphertext.as_ptr() as *const __m128i);
  
  // load key from memory into a single xmm register
  let key_register = _mm_loadu_si128(key.as_ptr() as *const __m128i);
  let mut inv_key_register = _mm_loadu_si128(key.as_ptr() as * const __m128i);
  inv_key_register = _mm_aesimc_si128(inv_key_register);

  // xor ciphertext with original key
  ct_register = _mm_xor_si128(ct_register, key_register);

  // apply r-1 rounds of inverse Rijndael using the same inverse key
  for _ in 1..rounds {
    ct_register = _mm_aesdec_si128(ct_register, inv_key_register);
  }
  
  // apply final decoding with original key
  ct_register = _mm_aesdeclast_si128(ct_register, key_register);

  // init memory for plaintext
  let mut plaintext = [0u8; 16];

  // store plaintext back into memory and return
  _mm_storeu_si128(plaintext.as_mut_ptr() as *mut __m128i, ct_register);

  // return plaintext
  plaintext
}

/// Generate a array of random bytes of length 3162 to be used as a sample block.
pub fn random_bytes_16() -> [u8; 16] {
  let mut bytes = [0u8; 16];
  rand::thread_rng().fill(&mut bytes[..]);
  bytes
}

#[inline(always)]
pub unsafe fn encode_pipelined(
  key: [u8; 16], 
  plaintexts: [[u8; 16]; 8],
  rounds: usize,
) -> [[u8; 16]; 4] {

  // load plaintext data from memory into a each xmm register
  let mut pt_0_register = _mm_loadu_si128(plaintexts[0].as_ptr() as *const __m128i);
  let mut pt_1_register = _mm_loadu_si128(plaintexts[1].as_ptr() as *const __m128i);
  let mut pt_2_register = _mm_loadu_si128(plaintexts[2].as_ptr() as *const __m128i);
  let mut pt_3_register = _mm_loadu_si128(plaintexts[3].as_ptr() as *const __m128i);
  // let mut pt_4_register = _mm_loadu_si128(plaintexts[4].as_ptr() as *const __m128i);
  // let mut pt_5_register = _mm_loadu_si128(plaintexts[5].as_ptr() as *const __m128i);
  // let mut pt_6_register = _mm_loadu_si128(plaintexts[6].as_ptr() as *const __m128i);
  // let mut pt_7_register = _mm_loadu_si128(plaintexts[7].as_ptr() as *const __m128i);
  
  // load key from memory into a single xmm register
  let key_register = _mm_loadu_si128(key.as_ptr() as *const __m128i);

  // xor each input with key
  pt_0_register = _mm_xor_si128(pt_0_register, key_register);
  pt_1_register = _mm_xor_si128(pt_1_register, key_register);
  pt_2_register = _mm_xor_si128(pt_2_register, key_register);
  pt_3_register = _mm_xor_si128(pt_3_register, key_register);
  // pt_4_register = _mm_xor_si128(pt_4_register, key_register);
  // pt_5_register = _mm_xor_si128(pt_5_register, key_register);
  // pt_6_register = _mm_xor_si128(pt_6_register, key_register);
  // pt_7_register = _mm_xor_si128(pt_7_register, key_register);

  // call r-1 rounds of Rijndael using AES-NI with same key for now
  for _ in 1..rounds {
    pt_0_register = _mm_aesenc_si128(pt_0_register, key_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_register);
    // pt_4_register = _mm_aesenc_si128(pt_4_register, key_register);
    // pt_5_register = _mm_aesenc_si128(pt_5_register, key_register);
    // pt_6_register = _mm_aesenc_si128(pt_6_register, key_register);
    // pt_7_register = _mm_aesenc_si128(pt_7_register, key_register);
  }
  
  // encode final round for each
  pt_0_register = _mm_aesenclast_si128(pt_0_register, key_register);
  pt_1_register = _mm_aesenclast_si128(pt_1_register, key_register);
  pt_2_register = _mm_aesenclast_si128(pt_2_register, key_register);
  pt_3_register = _mm_aesenclast_si128(pt_3_register, key_register);
  // pt_4_register = _mm_aesenclast_si128(pt_4_register, key_register);
  // pt_5_register = _mm_aesenclast_si128(pt_5_register, key_register);
  // pt_6_register = _mm_aesenclast_si128(pt_6_register, key_register);
  // pt_7_register = _mm_aesenclast_si128(pt_7_register, key_register);
  
  // init memory for ciphertexts
  let mut ciphertext_0 = [0u8; 16];
  let mut ciphertext_1 = [0u8; 16];
  let mut ciphertext_2 = [0u8; 16];
  let mut ciphertext_3 = [0u8; 16];
  // let mut ciphertext_4 = [0u8; 16];
  // let mut ciphertext_5 = [0u8; 16];
  // let mut ciphertext_6= [0u8; 16];
  // let mut ciphertext_7 = [0u8; 16];

  // store ciphertexts back into memory and return
  _mm_storeu_si128(ciphertext_0.as_mut_ptr() as *mut __m128i, pt_0_register);
  _mm_storeu_si128(ciphertext_1.as_mut_ptr() as *mut __m128i, pt_1_register);
  _mm_storeu_si128(ciphertext_2.as_mut_ptr() as *mut __m128i, pt_2_register);
  _mm_storeu_si128(ciphertext_3.as_mut_ptr() as *mut __m128i, pt_3_register);
  // _mm_storeu_si128(ciphertext_4.as_mut_ptr() as *mut __m128i, pt_4_register);
  // _mm_storeu_si128(ciphertext_5.as_mut_ptr() as *mut __m128i, pt_5_register);
  // _mm_storeu_si128(ciphertext_6.as_mut_ptr() as *mut __m128i, pt_6_register);
  // _mm_storeu_si128(ciphertext_7.as_mut_ptr() as *mut __m128i, pt_7_register);

  // return ciphertexts
  [
    ciphertext_0, 
    ciphertext_1, 
    ciphertext_2, 
    ciphertext_3,
    // ciphertext_4,
    // ciphertext_5,
    // ciphertext_6,
    // ciphertext_7,
  ]
}

#[inline(always)]
pub unsafe fn encode_pipelined_with_keys(
  keys: [[u8; 16]; 96], 
  plaintexts: [[u8; 16]; 8],
  rounds: usize,
) -> [[u8; 16]; 4] {

  // load plaintext data from memory into a each xmm register
  let mut pt_0_register = _mm_loadu_si128(plaintexts[0].as_ptr() as *const __m128i);
  let mut pt_1_register = _mm_loadu_si128(plaintexts[1].as_ptr() as *const __m128i);
  let mut pt_2_register = _mm_loadu_si128(plaintexts[2].as_ptr() as *const __m128i);
  let mut pt_3_register = _mm_loadu_si128(plaintexts[3].as_ptr() as *const __m128i);
  
  // load key from memory into a single xmm register
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
  let key_11_register = _mm_loadu_si128(keys[11].as_ptr() as *const __m128i);
  let key_12_register = _mm_loadu_si128(keys[12].as_ptr() as *const __m128i);
  let key_13_register = _mm_loadu_si128(keys[13].as_ptr() as *const __m128i);
  let key_14_register = _mm_loadu_si128(keys[14].as_ptr() as *const __m128i);
  let key_15_register = _mm_loadu_si128(keys[15].as_ptr() as *const __m128i);
  let key_16_register = _mm_loadu_si128(keys[16].as_ptr() as *const __m128i);
  let key_17_register = _mm_loadu_si128(keys[17].as_ptr() as *const __m128i);
  let key_18_register = _mm_loadu_si128(keys[18].as_ptr() as *const __m128i);
  let key_19_register = _mm_loadu_si128(keys[19].as_ptr() as *const __m128i);
  let key_20_register = _mm_loadu_si128(keys[20].as_ptr() as *const __m128i);
  let key_21_register = _mm_loadu_si128(keys[21].as_ptr() as *const __m128i);
  let key_22_register = _mm_loadu_si128(keys[22].as_ptr() as *const __m128i);
  let key_23_register = _mm_loadu_si128(keys[23].as_ptr() as *const __m128i);

  // xor each input with key
  pt_0_register = _mm_xor_si128(pt_0_register, key_0_register);
  pt_1_register = _mm_xor_si128(pt_1_register, key_0_register);
  pt_2_register = _mm_xor_si128(pt_2_register, key_0_register);
  pt_3_register = _mm_xor_si128(pt_3_register, key_0_register);

  // call r-1 rounds of Rijndael using AES-NI with same key for now
  for _ in 1..(rounds / 22) {
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

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_10_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_10_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_10_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_10_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_11_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_11_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_11_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_11_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_12_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_12_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_12_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_12_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_13_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_13_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_13_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_13_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_14_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_14_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_14_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_14_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_15_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_15_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_15_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_15_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_16_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_16_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_16_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_16_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_17_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_17_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_17_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_17_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_18_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_18_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_18_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_18_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_19_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_19_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_19_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_19_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_20_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_20_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_20_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_20_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_21_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_21_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_21_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_21_register);

    pt_0_register = _mm_aesenc_si128(pt_0_register, key_22_register);
    pt_1_register = _mm_aesenc_si128(pt_1_register, key_22_register);
    pt_2_register = _mm_aesenc_si128(pt_2_register, key_22_register);
    pt_3_register = _mm_aesenc_si128(pt_3_register, key_22_register);
  }
  
  // encode final round for each
  pt_0_register = _mm_aesenclast_si128(pt_0_register, key_23_register);
  pt_1_register = _mm_aesenclast_si128(pt_1_register, key_23_register);
  pt_2_register = _mm_aesenclast_si128(pt_2_register, key_23_register);
  pt_3_register = _mm_aesenclast_si128(pt_3_register, key_23_register);
  
  // init memory for ciphertexts
  let mut ciphertext_0 = [0u8; 16];
  let mut ciphertext_1 = [0u8; 16];
  let mut ciphertext_2 = [0u8; 16];
  let mut ciphertext_3 = [0u8; 16];

  // store ciphertexts back into memory and return
  _mm_storeu_si128(ciphertext_0.as_mut_ptr() as *mut __m128i, pt_0_register);
  _mm_storeu_si128(ciphertext_1.as_mut_ptr() as *mut __m128i, pt_1_register);
  _mm_storeu_si128(ciphertext_2.as_mut_ptr() as *mut __m128i, pt_2_register);
  _mm_storeu_si128(ciphertext_3.as_mut_ptr() as *mut __m128i, pt_3_register);
 
  // return ciphertexts
  [
    ciphertext_0, 
    ciphertext_1, 
    ciphertext_2, 
    ciphertext_3,
  ]
}

#[inline(always)]
pub unsafe fn encode_pipelined_with_keys_memory(
  keys: [[u8; 16]; 96], 
  plaintexts: [[u8; 16]; 8],
  rounds: usize,
) -> [[u8; 16]; 4] {

  // load plaintext data from memory into a each xmm register
  let mut pt_0_register = _mm_loadu_si128(plaintexts[0].as_ptr() as *const __m128i);
  let mut pt_1_register = _mm_loadu_si128(plaintexts[1].as_ptr() as *const __m128i);
  let mut pt_2_register = _mm_loadu_si128(plaintexts[2].as_ptr() as *const __m128i);
  let mut pt_3_register = _mm_loadu_si128(plaintexts[3].as_ptr() as *const __m128i);
  
  // load key from memory into a single xmm register
  let key_0_memory = keys[0].as_ptr() as *const __m128i;
  let key_1_memory = keys[1].as_ptr() as *const __m128i;
  let key_2_memory = keys[2].as_ptr() as *const __m128i;
  let key_3_memory = keys[3].as_ptr() as *const __m128i;
  let key_4_memory = keys[4].as_ptr() as *const __m128i;
  let key_5_memory = keys[5].as_ptr() as *const __m128i;
  let key_6_memory = keys[6].as_ptr() as *const __m128i;
  let key_7_memory = keys[7].as_ptr() as *const __m128i;
  let key_8_memory = keys[8].as_ptr() as *const __m128i;
  let key_9_memory = keys[9].as_ptr() as *const __m128i;
  let key_10_memory = keys[10].as_ptr() as *const __m128i;
  let key_11_memory = keys[11].as_ptr() as *const __m128i;
  let key_12_memory = keys[12].as_ptr() as *const __m128i;
  let key_13_memory = keys[13].as_ptr() as *const __m128i;
  let key_14_memory = keys[14].as_ptr() as *const __m128i;
  let key_15_memory = keys[15].as_ptr() as *const __m128i;
  let key_16_memory = keys[16].as_ptr() as *const __m128i;
  let key_17_memory = keys[17].as_ptr() as *const __m128i;
  let key_18_memory = keys[18].as_ptr() as *const __m128i;
  let key_19_memory = keys[19].as_ptr() as *const __m128i;
  let key_20_memory = keys[20].as_ptr() as *const __m128i;
  let key_21_memory = keys[21].as_ptr() as *const __m128i;
  let key_22_memory = keys[22].as_ptr() as *const __m128i;
  let key_23_memory = keys[23].as_ptr() as *const __m128i;

  // xor each input with key
  pt_0_register = _mm_xor_si128(pt_0_register, *key_0_memory);
  pt_1_register = _mm_xor_si128(pt_1_register, *key_0_memory);
  pt_2_register = _mm_xor_si128(pt_2_register, *key_0_memory);
  pt_3_register = _mm_xor_si128(pt_3_register, *key_0_memory);

  // call r-1 rounds of Rijndael using AES-NI with same key for now
  for _ in 1..(rounds / 22) {
    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_1_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_1_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_1_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_1_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_2_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_2_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_2_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_2_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_3_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_3_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_3_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_3_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_4_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_4_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_4_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_4_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_5_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_5_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_5_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_5_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_6_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_6_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_6_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_6_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_7_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_7_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_7_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_7_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_8_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_8_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_8_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_8_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_9_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_9_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_9_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_9_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_10_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_10_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_10_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_10_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_11_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_11_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_11_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_11_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_12_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_12_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_12_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_12_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_13_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_13_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_13_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_13_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_14_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_14_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_14_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_14_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_15_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_15_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_15_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_15_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_16_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_16_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_16_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_16_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_17_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_17_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_17_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_17_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_18_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_18_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_18_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_18_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_19_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_19_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_19_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_19_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_20_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_20_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_20_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_20_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_21_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_21_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_21_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_21_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_22_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_22_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_22_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_22_memory);
  }
  
  // encode final round for each
  pt_0_register = _mm_aesenclast_si128(pt_0_register, *key_23_memory);
  pt_1_register = _mm_aesenclast_si128(pt_1_register, *key_23_memory);
  pt_2_register = _mm_aesenclast_si128(pt_2_register, *key_23_memory);
  pt_3_register = _mm_aesenclast_si128(pt_3_register, *key_23_memory);
  
  // init memory for ciphertexts
  let mut ciphertext_0 = [0u8; 16];
  let mut ciphertext_1 = [0u8; 16];
  let mut ciphertext_2 = [0u8; 16];
  let mut ciphertext_3 = [0u8; 16];

  // store ciphertexts back into memory and return
  _mm_storeu_si128(ciphertext_0.as_mut_ptr() as *mut __m128i, pt_0_register);
  _mm_storeu_si128(ciphertext_1.as_mut_ptr() as *mut __m128i, pt_1_register);
  _mm_storeu_si128(ciphertext_2.as_mut_ptr() as *mut __m128i, pt_2_register);
  _mm_storeu_si128(ciphertext_3.as_mut_ptr() as *mut __m128i, pt_3_register);
 
  // return ciphertexts
  [
    ciphertext_0, 
    ciphertext_1, 
    ciphertext_2, 
    ciphertext_3,
  ]
}

#[inline(always)]
pub unsafe fn encode_pipelined_with_keys_memory_attacker(
  keys: [[u8; 16]; 96], 
  plaintexts: [[u8; 16]; 8],
  rounds: usize,
) -> [[u8; 16]; 4] {

  // load plaintext data from memory into a each xmm register
  let mut pt_0_register = _mm_loadu_si128(plaintexts[0].as_ptr() as *const __m128i);
  let mut pt_1_register = _mm_loadu_si128(plaintexts[0].as_ptr() as *const __m128i);
  let mut pt_2_register = _mm_loadu_si128(plaintexts[0].as_ptr() as *const __m128i);
  let mut pt_3_register = _mm_loadu_si128(plaintexts[0].as_ptr() as *const __m128i);
  
  // load key from memory into a single xmm register
  let key_0a_memory = keys[0].as_ptr() as *const __m128i;
  let key_0b_memory = keys[0].as_ptr() as *const __m128i;
  let key_0c_memory = keys[0].as_ptr() as *const __m128i;
  let key_0d_memory = keys[0].as_ptr() as *const __m128i;

  let key_1a_memory = keys[1].as_ptr() as *const __m128i;
  let key_1b_memory = keys[1].as_ptr() as *const __m128i;
  let key_1c_memory = keys[1].as_ptr() as *const __m128i;
  let key_1d_memory = keys[1].as_ptr() as *const __m128i;

  let key_2a_memory = keys[2].as_ptr() as *const __m128i;
  let key_2b_memory = keys[2].as_ptr() as *const __m128i;
  let key_2c_memory = keys[2].as_ptr() as *const __m128i;
  let key_2d_memory = keys[2].as_ptr() as *const __m128i;

  let key_3a_memory = keys[3].as_ptr() as *const __m128i;
  let key_3b_memory = keys[3].as_ptr() as *const __m128i;
  let key_3c_memory = keys[3].as_ptr() as *const __m128i;
  let key_3d_memory = keys[3].as_ptr() as *const __m128i;

  let key_4a_memory = keys[4].as_ptr() as *const __m128i;
  let key_4b_memory = keys[4].as_ptr() as *const __m128i;
  let key_4c_memory = keys[4].as_ptr() as *const __m128i;
  let key_4d_memory = keys[4].as_ptr() as *const __m128i;

  let key_5a_memory = keys[5].as_ptr() as *const __m128i;
  let key_5b_memory = keys[5].as_ptr() as *const __m128i;
  let key_5c_memory = keys[5].as_ptr() as *const __m128i;
  let key_5d_memory = keys[5].as_ptr() as *const __m128i;
  
  let key_6a_memory = keys[6].as_ptr() as *const __m128i;
  let key_6b_memory = keys[6].as_ptr() as *const __m128i;
  let key_6c_memory = keys[6].as_ptr() as *const __m128i;
  let key_6d_memory = keys[6].as_ptr() as *const __m128i;
  
  let key_7a_memory = keys[7].as_ptr() as *const __m128i;
  let key_7b_memory = keys[7].as_ptr() as *const __m128i;
  let key_7c_memory = keys[7].as_ptr() as *const __m128i;
  let key_7d_memory = keys[7].as_ptr() as *const __m128i;
  
  let key_8a_memory = keys[8].as_ptr() as *const __m128i;
  let key_8b_memory = keys[8].as_ptr() as *const __m128i;
  let key_8c_memory = keys[8].as_ptr() as *const __m128i;
  let key_8d_memory = keys[8].as_ptr() as *const __m128i;
  
  let key_9a_memory = keys[9].as_ptr() as *const __m128i;
  let key_9b_memory = keys[9].as_ptr() as *const __m128i;
  let key_9c_memory = keys[9].as_ptr() as *const __m128i;
  let key_9d_memory = keys[9].as_ptr() as *const __m128i;
  
  let key_10a_memory = keys[10].as_ptr() as *const __m128i;
  let key_10b_memory = keys[10].as_ptr() as *const __m128i;
  let key_10c_memory = keys[10].as_ptr() as *const __m128i;
  let key_10d_memory = keys[10].as_ptr() as *const __m128i;
  
  let key_11a_memory = keys[11].as_ptr() as *const __m128i;
  let key_11b_memory = keys[11].as_ptr() as *const __m128i;
  let key_11c_memory = keys[11].as_ptr() as *const __m128i;
  let key_11d_memory = keys[11].as_ptr() as *const __m128i;
  
  let key_12a_memory = keys[12].as_ptr() as *const __m128i;
  let key_12b_memory = keys[12].as_ptr() as *const __m128i;
  let key_12c_memory = keys[12].as_ptr() as *const __m128i;
  let key_12d_memory = keys[12].as_ptr() as *const __m128i;
  
  let key_13a_memory = keys[13].as_ptr() as *const __m128i;
  let key_13b_memory = keys[13].as_ptr() as *const __m128i;
  let key_13c_memory = keys[13].as_ptr() as *const __m128i;
  let key_13d_memory = keys[13].as_ptr() as *const __m128i;
  
  let key_14a_memory = keys[14].as_ptr() as *const __m128i;
  let key_14b_memory = keys[14].as_ptr() as *const __m128i;
  let key_14c_memory = keys[14].as_ptr() as *const __m128i;
  let key_14d_memory = keys[14].as_ptr() as *const __m128i;
  
  let key_15a_memory = keys[15].as_ptr() as *const __m128i;
  let key_15b_memory = keys[15].as_ptr() as *const __m128i;
  let key_15c_memory = keys[15].as_ptr() as *const __m128i;
  let key_15d_memory = keys[15].as_ptr() as *const __m128i;
  
  let key_16a_memory = keys[16].as_ptr() as *const __m128i;
  let key_16b_memory = keys[16].as_ptr() as *const __m128i;
  let key_16c_memory = keys[16].as_ptr() as *const __m128i;
  let key_16d_memory = keys[16].as_ptr() as *const __m128i;
  
  let key_17a_memory = keys[17].as_ptr() as *const __m128i;
  let key_17b_memory = keys[17].as_ptr() as *const __m128i;
  let key_17c_memory = keys[17].as_ptr() as *const __m128i;
  let key_17d_memory = keys[17].as_ptr() as *const __m128i;
  
  let key_18a_memory = keys[18].as_ptr() as *const __m128i;
  let key_18b_memory = keys[18].as_ptr() as *const __m128i;
  let key_18c_memory = keys[18].as_ptr() as *const __m128i;
  let key_18d_memory = keys[18].as_ptr() as *const __m128i;
  
  let key_19a_memory = keys[19].as_ptr() as *const __m128i;
  let key_19b_memory = keys[19].as_ptr() as *const __m128i;
  let key_19c_memory = keys[19].as_ptr() as *const __m128i;
  let key_19d_memory = keys[19].as_ptr() as *const __m128i;
  
  let key_20a_memory = keys[20].as_ptr() as *const __m128i;
  let key_20b_memory = keys[20].as_ptr() as *const __m128i;
  let key_20c_memory = keys[20].as_ptr() as *const __m128i;
  let key_20d_memory = keys[20].as_ptr() as *const __m128i;

  let key_21a_memory = keys[21].as_ptr() as *const __m128i;
  let key_21b_memory = keys[21].as_ptr() as *const __m128i;
  let key_21c_memory = keys[21].as_ptr() as *const __m128i;
  let key_21d_memory = keys[21].as_ptr() as *const __m128i;
  
  let key_22a_memory = keys[22].as_ptr() as *const __m128i;
  let key_22b_memory = keys[22].as_ptr() as *const __m128i;
  let key_22c_memory = keys[22].as_ptr() as *const __m128i;
  let key_22d_memory = keys[22].as_ptr() as *const __m128i;
  
  let key_23a_memory = keys[23].as_ptr() as *const __m128i;
  let key_23b_memory = keys[23].as_ptr() as *const __m128i;
  let key_23c_memory = keys[23].as_ptr() as *const __m128i;
  let key_23d_memory = keys[23].as_ptr() as *const __m128i;

  // xor each input with key
  pt_0_register = _mm_xor_si128(pt_0_register, *key_0a_memory);
  pt_1_register = _mm_xor_si128(pt_1_register, *key_0b_memory);
  pt_2_register = _mm_xor_si128(pt_2_register, *key_0c_memory);
  pt_3_register = _mm_xor_si128(pt_3_register, *key_0d_memory);

  // call r-1 rounds of Rijndael using AES-NI with same key for now
  for _ in 1..(rounds / 22) {
    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_1a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_1b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_1c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_1d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_2a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_2b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_2c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_2d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_3a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_3b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_3c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_3d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_4a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_4b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_4c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_4d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_5a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_5b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_5c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_5d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_6a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_6b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_6c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_6d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_7a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_7b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_7c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_7d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_8a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_8b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_8c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_8d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_9a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_9b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_9c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_9d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_10a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_10b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_10c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_10d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_11a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_11b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_11c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_11d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_12a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_12b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_12c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_12d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_13a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_13b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_13c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_13d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_14a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_14b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_14c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_14d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_15a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_15b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_15c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_15d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_16a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_16b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_16c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_16d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_17a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_17b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_17c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_17d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_18a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_18b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_18c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_18d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_19a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_19b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_19c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_19d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_20a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_20b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_20c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_20d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_21a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_21b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_21c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_21d_memory);

    pt_0_register = _mm_aesenc_si128(pt_0_register, *key_22a_memory);
    pt_1_register = _mm_aesenc_si128(pt_1_register, *key_22b_memory);
    pt_2_register = _mm_aesenc_si128(pt_2_register, *key_22c_memory);
    pt_3_register = _mm_aesenc_si128(pt_3_register, *key_22d_memory);
  }
  
  // encode final round for each
  pt_0_register = _mm_aesenclast_si128(pt_0_register, *key_23a_memory);
  pt_1_register = _mm_aesenclast_si128(pt_1_register, *key_23b_memory);
  pt_2_register = _mm_aesenclast_si128(pt_2_register, *key_23c_memory);
  pt_3_register = _mm_aesenclast_si128(pt_3_register, *key_23d_memory);
  
  // init memory for ciphertexts
  let mut ciphertext_0 = [0u8; 16];
  let mut ciphertext_1 = [0u8; 16];
  let mut ciphertext_2 = [0u8; 16];
  let mut ciphertext_3 = [0u8; 16];

  // store ciphertexts back into memory and return
  _mm_storeu_si128(ciphertext_0.as_mut_ptr() as *mut __m128i, pt_0_register);
  _mm_storeu_si128(ciphertext_1.as_mut_ptr() as *mut __m128i, pt_1_register);
  _mm_storeu_si128(ciphertext_2.as_mut_ptr() as *mut __m128i, pt_2_register);
  _mm_storeu_si128(ciphertext_3.as_mut_ptr() as *mut __m128i, pt_3_register);
 
  // return ciphertexts
  [
    ciphertext_0, 
    ciphertext_1, 
    ciphertext_2, 
    ciphertext_3,
  ]
}
