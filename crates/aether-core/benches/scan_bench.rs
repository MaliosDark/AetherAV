//! Throughput benchmarks for the hot scan paths.
//!
//! Run with `cargo bench -p aether-core`. The numbers that matter for an AV
//! engine are MB/s of hashing and per-buffer scan latency, so we report
//! throughput over a representative buffer size.

use aether_config::Config;
use aether_core::Scanner;
use aether_signatures::hash_bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::path::Path;

/// A pseudo-random-ish buffer (deterministic) standing in for a binary sample.
fn sample(size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_bytes");
    for &size in &[4 * 1024usize, 256 * 1024, 4 * 1024 * 1024] {
        let data = sample(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| hash_bytes(std::hint::black_box(d)));
        });
    }
    group.finish();
}

fn bench_scan(c: &mut Criterion) {
    // Heuristics-only scanner (no on-disk assets) keeps the bench hermetic.
    let mut cfg = Config::default();
    cfg.engines.hash = false;
    cfg.engines.yara = false;
    let scanner = Scanner::new(cfg).unwrap();
    let path = Path::new("bench.bin");

    let mut group = c.benchmark_group("scan_bytes");
    for &size in &[64 * 1024usize, 1024 * 1024] {
        let data = sample(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| scanner.scan_bytes(path, std::hint::black_box(d)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_hashing, bench_scan);
criterion_main!(benches);
