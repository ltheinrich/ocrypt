use crate::bits::{from_str, to_u8, OwnedBits};
use crate::des::{crypt_64, gen_keys};
use crate::{Error, Result};

pub fn encrypt(plaintext: &str, password: &str) -> Result<(OwnedBits, u8)> {
    if password.as_bytes().len() != 24 {
        return Error::SizeError.into();
    }

    let mut data = from_str(plaintext);
    let space = 64 - (data.len() % 64);
    while data.len() % 64 != 0 {
        data.push(false);
    }

    let password_bits = from_str(password);
    let keys1 = gen_keys(&password_bits[0..64])?;
    let mut keys2 = gen_keys(&password_bits[64..128])?;
    let keys3 = gen_keys(&password_bits[128..192])?;
    keys2.reverse();

    let mut blocks = Vec::with_capacity(data.len());
    for i in 0..data.len() / 64 {
        let mut block = crypt_64(&data[64 * i..64 * i + 64], &keys1)?;
        block = crypt_64(&block, &keys2)?;
        block = crypt_64(&block, &keys3)?;
        blocks.append(&mut block);
    }

    Ok((blocks, if space == 64 { 0 } else { space as u8 }))
}

pub fn decrypt(cipher: OwnedBits, password: &str, space: u8) -> Result<String> {
    if password.as_bytes().len() != 24 {
        return Error::SizeError.into();
    }

    let password_bits = from_str(password);
    let mut keys1 = gen_keys(&password_bits[0..64])?;
    let keys2 = gen_keys(&password_bits[64..128])?;
    let mut keys3 = gen_keys(&password_bits[128..192])?;
    keys1.reverse();
    keys3.reverse();

    let mut blocks = Vec::with_capacity(cipher.len());
    for i in 0..cipher.len() / 64 {
        let mut block = crypt_64(&cipher[64 * i..64 * i + 64], &keys3)?;
        block = crypt_64(&block, &keys2)?;
        block = crypt_64(&block, &keys1)?;
        blocks.append(&mut block);
    }
    blocks.truncate(blocks.len() - space as usize);

    let mut plaintext = Vec::with_capacity(blocks.len() / 8);
    for i in 0..blocks.len() / 8 {
        plaintext.push(to_u8(&blocks[8 * i..8 * i + 8])?);
    }

    String::from_utf8(plaintext).or_else(Error::from)
}

#[test]
fn test_encrypt_decrypt() {
    let (cipher, space) = encrypt("Das hier ist ein Test", "8-bytes!1234567890123456").unwrap();
    cipher
        .iter()
        .for_each(|v| if *v { print!("1") } else { print!("0") });
    let plaintext = decrypt(cipher, "8-bytes!1234567890123456", space).unwrap();
    assert_eq!(&plaintext, "Das hier ist ein Test");
}
