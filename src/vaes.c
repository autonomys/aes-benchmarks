#include <immintrin.h>

__attribute__((target("aes")))
void aesni_enc_block(
  const unsigned char* input,
  const unsigned char* key,  
  size_t rounds,
  unsigned char* output
) {
  __m128i feedback, key_0, key_1, key_2, key_3, key_4, key_5, key_6, key_7, key_8, key_9, key_10;

  // load the INPUT
  feedback = _mm_loadu_si128((__m128i*)input);
  key_0 = _mm_loadu_si128((__m128i*)(&key[16 * 0]));
  key_1 = _mm_loadu_si128((__m128i*)(&key[16 * 1]));
  key_2 = _mm_loadu_si128((__m128i*)(&key[16 * 2]));
  key_3 = _mm_loadu_si128((__m128i*)(&key[16 * 3]));
  key_4 = _mm_loadu_si128((__m128i*)(&key[16 * 4]));
  key_5 = _mm_loadu_si128((__m128i*)(&key[16 * 5]));
  key_6 = _mm_loadu_si128((__m128i*)(&key[16 * 6]));
  key_7 = _mm_loadu_si128((__m128i*)(&key[16 * 7]));
  key_8 = _mm_loadu_si128((__m128i*)(&key[16 * 8]));
  key_9 = _mm_loadu_si128((__m128i*)(&key[16 * 9]));
  key_10 = _mm_loadu_si128((__m128i*)(&key[16 * 10]));

  for (size_t i = 0; i < rounds; i++) {
    // xor with first key (whitening)
    feedback = _mm_xor_si128(feedback, key_0);

    // 9 rounds of aesenc
    feedback = _mm_aesenc_si128(feedback, key_1);
    feedback = _mm_aesenc_si128(feedback, key_2);
    feedback = _mm_aesenc_si128(feedback, key_3);
    feedback = _mm_aesenc_si128(feedback, key_4);
    feedback = _mm_aesenc_si128(feedback, key_5);
    feedback = _mm_aesenc_si128(feedback, key_6);
    feedback = _mm_aesenc_si128(feedback, key_7);
    feedback = _mm_aesenc_si128(feedback, key_8);
    feedback = _mm_aesenc_si128(feedback, key_9);
    
    // last round
    feedback = _mm_aesenclast_si128(feedback, key_10);
  }
  
  // store to output 
  _mm_storeu_si128(((__m128i*)output), feedback); 
}

__attribute__((target("aes")))
void aesni_dec_block(
  const unsigned char* input,
  const unsigned char* key,  
  size_t rounds,
  unsigned char* output
) {
  __m128i feedback, key_0, key_1, key_2, key_3, key_4, key_5, key_6, key_7, key_8, key_9, key_10, inv_key_1, inv_key_2, inv_key_3, inv_key_4, inv_key_5, inv_key_6, inv_key_7, inv_key_8, inv_key_9;

  // load the input
  feedback = _mm_loadu_si128((__m128i*)input);

  // load and invert keys
  key_0 = _mm_loadu_si128((__m128i*)(&key[16 * 0]));

  key_1 = _mm_loadu_si128((__m128i*)(&key[16 * 1]));
  inv_key_1 = _mm_aesimc_si128(key_1);

  key_2 = _mm_loadu_si128((__m128i*)(&key[16 * 2]));
  inv_key_2 = _mm_aesimc_si128(key_2);

  key_3 = _mm_loadu_si128((__m128i*)(&key[16 * 3]));
  inv_key_3 = _mm_aesimc_si128(key_3);

  key_4 = _mm_loadu_si128((__m128i*)(&key[16 * 4]));
  inv_key_4 = _mm_aesimc_si128(key_4);

  key_5 = _mm_loadu_si128((__m128i*)(&key[16 * 5]));
  inv_key_5 = _mm_aesimc_si128(key_5);

  key_6 = _mm_loadu_si128((__m128i*)(&key[16 * 6]));
  inv_key_6 = _mm_aesimc_si128(key_6);

  key_7 = _mm_loadu_si128((__m128i*)(&key[16 * 7]));
  inv_key_7 = _mm_aesimc_si128(key_7);

  key_8 = _mm_loadu_si128((__m128i*)(&key[16 * 8]));
  inv_key_8 = _mm_aesimc_si128(key_8);

  key_9 = _mm_loadu_si128((__m128i*)(&key[16 * 9]));
  inv_key_9 = _mm_aesimc_si128(key_9);

  key_10 = _mm_loadu_si128((__m128i*)(&key[16 * 10]));

  for (size_t i = 0; i < rounds; i++) {
    // xor with first key (whitening)
    feedback = _mm_xor_si128(feedback, key_10);

    // 9 rounds of aesenc
    feedback = _mm_aesenc_si128(feedback, inv_key_9);
    feedback = _mm_aesenc_si128(feedback, inv_key_8);
    feedback = _mm_aesenc_si128(feedback, inv_key_7);
    feedback = _mm_aesenc_si128(feedback, inv_key_6);
    feedback = _mm_aesenc_si128(feedback, inv_key_5);
    feedback = _mm_aesenc_si128(feedback, inv_key_4);
    feedback = _mm_aesenc_si128(feedback, inv_key_3);
    feedback = _mm_aesenc_si128(feedback, inv_key_2);
    feedback = _mm_aesenc_si128(feedback, inv_key_1);
    
    // last round
    feedback = _mm_aesenclast_si128(feedback, key_0);
  }
  
  // store to output 
  _mm_storeu_si128(((__m128i*)output), feedback); 
}

__attribute__((target("aes,avx512f,vaes")))
void vaesni_enc_block(
  const unsigned char* input,
  const unsigned char* key,  
  size_t rounds,
  unsigned char* output
) {
  __m512i feedback, key_0, key_1, key_2, key_3, key_4, key_5, key_6, key_7, key_8, key_9, key_10;

  // load the input
  feedback = _mm512_loadu_si512((__m512i*)input);
  key_0 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 0])));
  key_1 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 1])));
  key_2 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 2])));
  key_3 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 3])));
  key_4 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 4])));
  key_5 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 5])));
  key_6 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 6])));
  key_7 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 7])));
  key_8 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 8])));
  key_9 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 9])));
  key_10 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 10])));

  for (size_t i = 0; i < rounds; i++) {
    // xor with first key (whitening)
    feedback = _mm512_xor_si512(feedback, key_0);

    // 9 rounds of aesenc
    feedback = _mm512_aesenc_epi128(feedback, key_1);
    feedback = _mm512_aesenc_epi128(feedback, key_2);
    feedback = _mm512_aesenc_epi128(feedback, key_3);
    feedback = _mm512_aesenc_epi128(feedback, key_4);
    feedback = _mm512_aesenc_epi128(feedback, key_5);
    feedback = _mm512_aesenc_epi128(feedback, key_6);
    feedback = _mm512_aesenc_epi128(feedback, key_7);
    feedback = _mm512_aesenc_epi128(feedback, key_8);
    feedback = _mm512_aesenc_epi128(feedback, key_9);
    
    // last round
    feedback = _mm512_aesenclast_epi128(feedback, key_10);
  }
  
  // store to output 
  _mm512_storeu_si512(((__m512i*)output), feedback); 
}

__attribute__((target("aes,avx512f,vaes")))
void vaesni_enc_block_x3(
  const unsigned char* input,
  const unsigned char* key,  
  size_t rounds,
  unsigned char* output_0,
  unsigned char* output_1,
  unsigned char* output_2
) {
  __m512i feedback_0, feedback_1, feedback_2; 
  __m512i key_0, key_1, key_2, key_3, key_4, key_5, key_6, key_7, key_8, key_9, key_10;

  // load the input
  feedback_0 = _mm512_loadu_si512((__m512i*)(&input[64 * 0]));
  feedback_1 = _mm512_loadu_si512((__m512i*)(&input[64 * 1]));
  feedback_2 = _mm512_loadu_si512((__m512i*)(&input[64 * 2]));
  // feedback_3 = _mm512_loadu_si512((__m512i*)(&input[64 * 3]));

  key_0 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 0])));
  key_1 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 1])));
  key_2 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 2])));
  key_3 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 3])));
  key_4 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 4])));
  key_5 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 5])));
  key_6 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 6])));
  key_7 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 7])));
  key_8 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 8])));
  key_9 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 9])));
  key_10 = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&key[16 * 10])));

  for (size_t i = 0; i < rounds; i++) {
    // xor with first key (whitening)
    feedback_0 = _mm512_xor_si512(feedback_0, key_0);
    feedback_1 = _mm512_xor_si512(feedback_1, key_0);
    feedback_2 = _mm512_xor_si512(feedback_2, key_0);
    // feedback_3 = _mm512_xor_si512(feedback_3, key_0);

    // 9 rounds of aesenc
    feedback_0 = _mm512_aesenc_epi128(feedback_0, key_1);
    feedback_1 = _mm512_aesenc_epi128(feedback_1, key_1);
    feedback_2 = _mm512_aesenc_epi128(feedback_2, key_1);
    // feedback_3 = _mm512_aesenc_epi128(feedback_3, key_1);

    feedback_0 = _mm512_aesenc_epi128(feedback_0, key_2);
    feedback_1 = _mm512_aesenc_epi128(feedback_1, key_2);
    feedback_2 = _mm512_aesenc_epi128(feedback_2, key_2);
    // feedback_3 = _mm512_aesenc_epi128(feedback_3, key_2);

    feedback_0 = _mm512_aesenc_epi128(feedback_0, key_3);
    feedback_1 = _mm512_aesenc_epi128(feedback_1, key_3);
    feedback_2 = _mm512_aesenc_epi128(feedback_2, key_3);
    // feedback_3 = _mm512_aesenc_epi128(feedback_3, key_3);

    feedback_0 = _mm512_aesenc_epi128(feedback_0, key_4);
    feedback_1 = _mm512_aesenc_epi128(feedback_1, key_4);
    feedback_2 = _mm512_aesenc_epi128(feedback_2, key_4);
    // feedback_3 = _mm512_aesenc_epi128(feedback_3, key_4);

    feedback_0 = _mm512_aesenc_epi128(feedback_0, key_5);
    feedback_1 = _mm512_aesenc_epi128(feedback_1, key_5);
    feedback_2 = _mm512_aesenc_epi128(feedback_2, key_5);
    // feedback_3 = _mm512_aesenc_epi128(feedback_3, key_5);

    feedback_0 = _mm512_aesenc_epi128(feedback_0, key_6);
    feedback_1 = _mm512_aesenc_epi128(feedback_1, key_6);
    feedback_2 = _mm512_aesenc_epi128(feedback_2, key_6);
    // feedback_3 = _mm512_aesenc_epi128(feedback_3, key_6);

    feedback_0 = _mm512_aesenc_epi128(feedback_0, key_7);
    feedback_1 = _mm512_aesenc_epi128(feedback_1, key_7);
    feedback_2 = _mm512_aesenc_epi128(feedback_2, key_7);
    // feedback_3 = _mm512_aesenc_epi128(feedback_3, key_7);

    feedback_0 = _mm512_aesenc_epi128(feedback_0, key_8);
    feedback_1 = _mm512_aesenc_epi128(feedback_1, key_8);
    feedback_2 = _mm512_aesenc_epi128(feedback_2, key_8);
    // feedback_3 = _mm512_aesenc_epi128(feedback_3, key_8);

    feedback_0 = _mm512_aesenc_epi128(feedback_0, key_9);
    feedback_1 = _mm512_aesenc_epi128(feedback_1, key_9);
    feedback_2 = _mm512_aesenc_epi128(feedback_2, key_9);
    // feedback_3 = _mm512_aesenc_epi128(feedback_3, key_9);
    
    // last round
    feedback_0 = _mm512_aesenclast_epi128(feedback_0, key_10);
    feedback_1 = _mm512_aesenclast_epi128(feedback_1, key_10);
    feedback_2 = _mm512_aesenclast_epi128(feedback_2, key_10);
    // feedback_3 = _mm512_aesenclast_epi128(feedback_3, key_10);
  }
  
  // store to output 
  _mm512_storeu_si512(((__m512i*)output_0), feedback_0); 
  _mm512_storeu_si512(((__m512i*)output_1), feedback_1); 
  _mm512_storeu_si512(((__m512i*)output_2), feedback_2); 
}