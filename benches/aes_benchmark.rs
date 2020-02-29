use criterion::{criterion_group, criterion_main, Criterion, black_box};

pub fn criterion_benchmark(c: &mut Criterion) {

    // generate a fifteen random keys of 16 bytes each
    let keys = [
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
    ];

    let flat_keys = random_bytes_176();

    // generate eight random inputs of 16 bytes each
    let inputs = [
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
    ];

    let flat_inputs_64 = random_bytes_64();

    let flat_inputs_192 = random_bytes_192();

    let rounds = 4096;

    // let ciphertext = unsafe { encode(keys[0], plaintexts[0], 660000) }; 

    let mut group = c.benchmark_group("aes");

    // Bench Look-Up-Table (LUT) method using aes_frast crate

    // use aes_frast::aes_core::{setkey_enc_k128, block_enc_k128};

    // let mut scheduled_keys: [u32; 44] = [0; 44];
    // let mut output: [u8; 16] = [0; 16];    
    // setkey_enc_k128(&keys[0], &mut scheduled_keys);

    // group.bench_function(
    //   "encode-lut", 
    //   |b| b.iter(
    //     || black_box(
    //         block_enc_k128(&inputs[0], &mut output, &scheduled_keys)
    //     )
    //   )
    // );

    // // // Bench bitslice method using aes_soft crate

    // use aes_soft::block_cipher_trait::generic_array::GenericArray;
    // use aes_soft::block_cipher_trait::BlockCipher;

    // let test_key = GenericArray::from_slice(&keys[0]);
    // let cipher = aes_soft::Aes128::new(&test_key);

    // let mut test_block = GenericArray::clone_from_slice(&inputs[0]);
    
    // group.bench_function(
    //   "encode-bitslice", 
    //   |b| b.iter(
    //     || black_box(
    //         cipher.encrypt_block(&mut test_block)
    //     )
    //   )
    // );

    // let mut test_block_8 = GenericArray::clone_from_slice(&[
    //   GenericArray::clone_from_slice(&inputs[0]),
    //   GenericArray::clone_from_slice(&inputs[1]),
    //   GenericArray::clone_from_slice(&inputs[2]),
    //   GenericArray::clone_from_slice(&inputs[3]),
    //   GenericArray::clone_from_slice(&inputs[4]),
    //   GenericArray::clone_from_slice(&inputs[5]),
    //   GenericArray::clone_from_slice(&inputs[6]),
    //   GenericArray::clone_from_slice(&inputs[7]),
    // ]);

    // group.bench_function(
    //   "encode-bitslice-8", 
    //   |b| b.iter(
    //     || black_box(
    //       cipher.encrypt_blocks(&mut test_block_8)
    //     )
    //   )
    // );

    use aes_benchmarks::*;

    group.bench_function(
      "encode-aes-ni-direct-single", 
      |b| b.iter(
        || unsafe { 
          black_box(
            encode_aes_ni_128(keys, inputs[0], 1)
          ) 
        }
      )
    );

    group.bench_function(
      "encode-aes-ni-c-direct-single", 
      |b| b.iter(
        || unsafe { 
          black_box(
            encode_aes_ni_c_128(flat_keys, inputs[0], 1)
          ) 
        }
      )
    );

    group.bench_function(
      "encode-vaes-ni-c-direct-single", 
      |b| b.iter(
        || unsafe { 
          black_box(
            encode_vaes_ni_c_512(flat_keys, flat_inputs_64, 1)
          ) 
        }
      )
    );

    group.bench_function(
      "encode-aes-ni-x4-direct-single", 
      |b| b.iter(
        || unsafe { 
          black_box(
            encode_aes_ni_128_pipelined_x4(keys, [
              inputs[0],
              inputs[1],
              inputs[2],
              inputs[3],
            ],
            1,
          ) 
        )
       }
      )
    );
    
    group.bench_function(
      "encode-aes-ni-x8-direct-single", 
      |b| b.iter(
        || unsafe { 
          black_box(
            encode_aes_ni_128_pipelined_x8(keys, [
              inputs[0],
              inputs[1],
              inputs[2],
              inputs[3],
              inputs[4],
              inputs[5],
              inputs[6],
              inputs[7],
            ],
            1,
          ) 
        )
       }
      )
    );

    group.bench_function(
      "encode-vaes-ni-x3-direct-single", 
      |b| b.iter(
        || unsafe { 
          black_box(
            encode_vaes_ni_c_512_x3(flat_keys, flat_inputs_192, 1) 
        )
       }
      )
    );

    group.bench_function(
      "encode-aes-ni-direct-iterated", 
      |b| b.iter(
        || unsafe { 
          black_box(
            encode_aes_ni_128(keys, inputs[0], 4096)
          ) 
        }
      )
    );

    group.bench_function(
      "encode-aes-ni-c-direct-iterated", 
      |b| b.iter(
        || unsafe { 
          black_box(
            encode_aes_ni_c_128(flat_keys, inputs[0], 4096)
          ) 
        }
      )
    );

    group.bench_function(
      "encode-vaes-ni-c-direct-iterated", 
      |b| b.iter(
        || unsafe { 
          black_box(
            encode_vaes_ni_c_512(flat_keys, flat_inputs_64, 4096)
          ) 
        }
      )
    );

    group.bench_function(
      "encode-aes-ni-x4-direct-iterated", 
      |b| b.iter(
        || unsafe { 
          black_box(
            encode_aes_ni_128_pipelined_x4(keys, [
                inputs[0],
                inputs[1],
                inputs[2],
                inputs[3],
              ],
              rounds,
            ) 
          )
        }
      )
    );

    group.bench_function(
      "encode-aes-ni-x8-direct-iterated", 
      |b| b.iter(
        || unsafe { 
          black_box(
            encode_aes_ni_128_pipelined_x8(keys, [
                inputs[0],
                inputs[1],
                inputs[2],
                inputs[3],
                inputs[4],
                inputs[5],
                inputs[6],
                inputs[7],
              ],
              rounds,
            ) 
          )
        }
      )
    );

    group.bench_function(
      "encode-vaes-ni-x3-c-direct-iterated", 
      |b| b.iter(
        || unsafe { 
          black_box(
            encode_vaes_ni_c_512_x3(flat_keys, flat_inputs_192, 4096) 
          ) 
        }
      )
    );

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);