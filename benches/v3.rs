use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{Rng, SeedableRng, rngs::StdRng};
use xelis_hash::v3::*;

const FIXED_INPUT: &[u8] = b"Hello World from xelis hash v3!";

fn bench_zero_input(c: &mut Criterion) {
    let mut scratch_pad = ScratchPad::default();
    let input = [0u8; 112];
    c.bench_function("v3::zero_input", |b| b.iter(|| xelis_hash(&input, &mut scratch_pad)));
}

fn bench_fixed_input(c: &mut Criterion) {
    let mut scratch_pad = ScratchPad::default();
    c.bench_function("v3::fixed_input", |b| b.iter(|| xelis_hash(FIXED_INPUT, &mut scratch_pad)));
}

fn bench_pick_half(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let inputs: Vec<u64> = (0..1_000_000).map(|_| rng.gen()).collect();

    c.bench_function("v3::pick_half", |b| {
        b.iter(|| {
            // Iterate over pre-generated random seeds
            for &seed in &inputs {
                // Prevent compiler from optimizing away the call
                black_box(pick_half(black_box(seed)));
            }
        })
    });
}

fn bench_map_index(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let inputs: Vec<u64> = (0..1_000_000).map(|_| rng.gen()).collect();

    c.bench_function("v3::map_index", |b| {
        b.iter(|| {
            // Iterate over pre-generated random seeds
            for &seed in &inputs {
                // Prevent compiler from optimizing away the call
                black_box(map_index(black_box(seed)));
            }
        })
    });
}

criterion_group!(benches, bench_zero_input, bench_fixed_input, bench_pick_half, bench_map_index);
criterion_main!(benches);