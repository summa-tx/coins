use criterion::{criterion_group, criterion_main, Criterion};
use rmn_bip32::{
    backend::{Secp256k1Backend, curve::Secp256k1},
    xkeys::{Hint, XKey, XPriv}
};

fn derive_10_times(key: &XPriv) {
    let path: [u32; 10] = [0, 1, 2, 3, 4, 0x8000_0001, 0x8000_0002, 0x8000_0003, 0x8000_0004, 0x8000_0005];
    key.derive_path(&path[..]).unwrap();
}

pub fn bench_10(c: &mut Criterion) {
    let backend = Secp256k1::init();
    let seed: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let xpriv = XPriv::root_from_seed(
        &seed,
        Some(Hint::Legacy),
        &backend
    ).unwrap();

    c.bench_function("derive_10", |b| b.iter(|| derive_10_times(&xpriv)));
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = bench_10
}
criterion_main!(benches);
