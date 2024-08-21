use criterion::{criterion_group, criterion_main, Criterion};
use xelis_hash::v1::{xelis_hash, ScratchPad};

const FIXED_INPUT: &[u8] = b"Hello World from xelis hash v1!";

fn bench_zero_input(c: &mut Criterion) {
    let mut scratch_pad = ScratchPad::default();
    let input = [0u8; 200];
    c.bench_function("v1::zero_input", |b| b.iter(|| xelis_hash(&mut input.clone(), &mut scratch_pad)));
}

fn bench_fixed_input(c: &mut Criterion) {
    let mut scratch_pad = ScratchPad::default();
    let mut input = [0u8; 200];
    input[0..FIXED_INPUT.len()].copy_from_slice(FIXED_INPUT);

    c.bench_function("v1::fixed_input", |b| b.iter(|| xelis_hash(&mut input.clone(), &mut scratch_pad)));
}

criterion_group!(benches, bench_zero_input, bench_fixed_input);
criterion_main!(benches);