use criterion::{criterion_group, criterion_main, Criterion};
use aes_benchmarks::*;

pub fn criterion_benchmark(c: &mut Criterion) {

    let key = random_bytes_16();
    let plaintexts = [
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
      random_bytes_16(),
    ];
    let ciphertext = unsafe { encode(key, plaintexts[0], 10000000) }; 

    let mut group = c.benchmark_group("aes-ni-simple");

    group.bench_function(
      "encode", 
      |b| b.iter(
        || unsafe { encode(key, plaintexts[0], 10000000) }
      )
    );

    // group.bench_function(
    //   "decode", 
    //   |b| b.iter(
    //     || unsafe { decode(key, ciphertext, 100000) }
    //   )
    // );

    group.bench_function(
      "encode-pipelined", 
      |b| b.iter(
        || unsafe { encode_pipelined(key, plaintexts, 10000000) }
      )
    );

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);