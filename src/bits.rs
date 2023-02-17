use crate::{Error, Result};

pub type OwnedBits = Vec<bool>;
pub type Bits<'a> = &'a [bool];
pub type BitsMut<'a> = &'a mut [bool];
pub type PermutationTable<'a> = &'a [usize];
pub type ExpansionTable<'a> = &'a [usize; 48];
pub type SubstitutionTable<'a> = &'a [&'a [usize; 16]; 4];

/// Split byte slice in half (only for even sizes!)
pub fn split(data: Bits) -> (Bits, Bits) {
    (&data[..data.len() / 2], &data[data.len() / 2..])
}

/// Split byte slice in half (only for even sizes!)
pub fn split_owned(data: Bits) -> (OwnedBits, OwnedBits) {
    (
        data[..data.len() / 2].to_owned(),
        data[data.len() / 2..].to_owned(),
    )
}

#[test]
fn test_split() {
    assert_eq!(
        (&[true, false, false] as Bits, &[true, true, true] as Bits),
        split(&[true, false, false, true, true, true])
    );
    assert_eq!(
        (&[false, true] as Bits, &[true, false, false] as Bits),
        split(&[false, true, true, false, false])
    );
}

/// Change data values to XOR of data[i] and key[i]
pub fn xor(data: BitsMut, key: Bits) -> Result<()> {
    if data.len() != key.len() {
        return Error::SizeError.into();
    }

    for i in 0..data.len() {
        data[i] = data[i] ^ key[i];
    }

    Ok(())
}

#[test]
fn test_xor() {
    let data: BitsMut = &mut [true, false, false, true, true, false];
    xor(data, &[false, true, false, true, false, false]).unwrap();
    assert_eq!(data, &[true, true, false, false, true, false]);

    let mut data: OwnedBits = vec![true, false, false, true, true, false];
    xor(&mut data, &[false, true, false, true, false, false]).unwrap();
    assert_eq!(data, &[true, true, false, false, true, false]);
}

/// Return values for XOR of data[i] and key[i]
pub fn xor_copy<'a>(data: Bits, key: Bits) -> Result<OwnedBits> {
    if data.len() != key.len() {
        return Error::SizeError.into();
    }

    let copy = data
        .iter()
        .enumerate()
        .map(|(index, value)| value ^ key[index])
        .collect();
    Ok(copy)
}

#[test]
fn test_xor_copy() {
    let xor = xor_copy(
        &[true, false, false, true, true, false],
        &[false, true, false, true, false, false],
    )
    .unwrap();
    assert_eq!(&xor, &[true, true, false, false, true, false]);
}

pub fn to_u8(data: Bits) -> Result<u8> {
    if data.len() > 8 {
        return Error::SizeError.into();
    }

    let mut num = 0u8;
    for i in 0..data.len() {
        num += 2u8.pow((data.len() - i - 1) as u32) * data[i] as u8;
    }

    Ok(num)
}

#[test]
fn test_to_u8() {
    assert_eq!(
        148,
        to_u8(&[true, false, false, true, false, true, false, false]).unwrap()
    );
}

pub fn to_bits(mut num: u8) -> OwnedBits {
    let mut bits = vec![false; 8];
    for i in 0..8 {
        let m = num % 2;
        bits[7 - i] = m == 1;
        num /= 2;
    }

    bits
}

#[test]
fn test_to_bits() {
    assert_eq!(
        &[true, false, false, true, false, true, false, false] as Bits,
        &to_bits(148)
    );
}

pub fn from_str(text: &str) -> OwnedBits {
    let mut bits = Vec::with_capacity(text.len() * 8);
    for byte in text.as_bytes() {
        bits.append(&mut to_bits(*byte));
    }
    bits
}
