use criterion::{criterion_group, criterion_main, Criterion};
use aes_benchmarks::*;

pub fn criterion_benchmark(c: &mut Criterion) {

    let key = random_bytes_16();
    let plaintext = random_bytes_16();
    let ciphertext = unsafe { encode(key, plaintext, 1000) }; 

    let mut group = c.benchmark_group("aes-ni-simple");

    group.bench_function(
      "encode", 
      |b| b.iter(
        || unsafe { encode(key, plaintext, 1000) }
      )
    );

    group.bench_function(
      "decode", 
      |b| b.iter(
        || unsafe { decode(ciphertext, plaintext, 1000) }
      )
    );

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);