use criterion::{Criterion, black_box, criterion_group, criterion_main};
use des::Des;
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use ocrypt::des::{decrypt, encrypt};
use rand::distr::Alphanumeric;
use rand::{Rng, rng};

fn criterion_benchmark(c: &mut Criterion) {
    let bc = 38400;

    let key: String = rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let data: String = rng()
        .sample_iter(&Alphanumeric)
        .take(bc * 8)
        .map(char::from)
        .collect();
    let (encrypted, space) = encrypt(&data, &key).unwrap();

    c.bench_function("DES encryption (ocrypt)", |b| {
        b.iter(|| encrypt(black_box(&data), black_box(&key)))
    });

    c.bench_function("DES decryption (ocrypt)", |b| {
        b.iter(|| decrypt(black_box(&encrypted), black_box(&key), black_box(space)))
    });

    let key = GenericArray::from_slice(key.as_bytes());
    let cipher = Des::new(&key);

    let mut blocks: Vec<&GenericArray<u8, _>> = data
        .as_bytes()
        .chunks(8)
        .map(|data| GenericArray::from_slice(data))
        .collect();
    let mut encrypted_blocks = [GenericArray::from([0u8; 8]); 38400];

    for (i, block) in blocks.iter_mut().enumerate() {
        cipher.encrypt_block_b2b(block, &mut encrypted_blocks[i]);
    }

    for block in blocks.iter() {
        cipher.decrypt_block_b2b(block, &mut GenericArray::from([0u8; 8]));
    }

    c.bench_function("DES encryption (des)", |b| {
        b.iter(|| {
            for block in blocks.iter() {
                cipher.encrypt_block_b2b(block, &mut GenericArray::from([0u8; 8]));
            }
        })
    });

    c.bench_function("DES decryption (des)", |b| {
        b.iter(|| {
            for block in encrypted_blocks.iter() {
                cipher.decrypt_block_b2b(block, &mut GenericArray::from([0u8; 8]));
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
