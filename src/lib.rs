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