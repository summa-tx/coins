use blake2_rfc::blake2b::Blake2b;

pub type Blake2b160Digest = [u8; 20];

pub fn blake2b160(preimage: &[u8]) -> Blake2b160Digest {
    let mut ctx = Blake2b::new(20);
    ctx.update(preimage);
    let digest = ctx.finalize();

    let mut result = Blake2b160Digest::default();
    result[..].copy_from_slice(digest.as_bytes());
    result
}
