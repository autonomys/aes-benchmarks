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