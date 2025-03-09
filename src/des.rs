use std::mem::swap;

use crate::bits::{
    from_str, split_owned, to_bits, to_u8, xor, Bits, BitsMut, ExpansionTable, OwnedBits,
    PermutationTable, SubstitutionTable,
};
use crate::{Error, Result};

static IP_TABLE: PermutationTable = &[
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
static FP_TABLE: PermutationTable = &[
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];
static E_TABLE: ExpansionTable = &[
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];
static P_TABLE: PermutationTable = &[
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];
static S1_TABLE: SubstitutionTable = &[
    &[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    &[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    &[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    &[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
];
static S2_TABLE: SubstitutionTable = &[
    &[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    &[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    &[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    &[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
];
static S3_TABLE: SubstitutionTable = &[
    &[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    &[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    &[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    &[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
];
static S4_TABLE: SubstitutionTable = &[
    &[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    &[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    &[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    &[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
];
static S5_TABLE: SubstitutionTable = &[
    &[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    &[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    &[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    &[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
];
static S6_TABLE: SubstitutionTable = &[
    &[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    &[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    &[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    &[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
];
static S7_TABLE: SubstitutionTable = &[
    &[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    &[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    &[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    &[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
];
static S8_TABLE: SubstitutionTable = &[
    &[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    &[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    &[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    &[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
];
static PC1_TABLE: PermutationTable = &[
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];
static PC2_TABLE: PermutationTable = &[
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

type Bits8<'a> = (
    Bits<'a>,
    Bits<'a>,
    Bits<'a>,
    Bits<'a>,
    Bits<'a>,
    Bits<'a>,
    Bits<'a>,
    Bits<'a>,
);

pub fn encrypt(plaintext: &str, password: &str) -> Result<(OwnedBits, u8)> {
    let mut data = from_str(plaintext);
    let space = 64 - (data.len() % 64);
    while data.len() % 64 != 0 {
        data.push(false);
    }

    let keys = gen_keys(&from_str(password))?;
    let mut blocks = Vec::with_capacity(data.len());
    for i in 0..data.len() / 64 {
        let mut block = crypt_64(&data[64 * i..64 * i + 64], &keys)?;
        blocks.append(&mut block);
    }

    Ok((blocks, if space == 64 { 0 } else { space as u8 }))
}

pub fn decrypt(cipher: Bits, password: &str, space: u8) -> Result<String> {
    let mut keys = gen_keys(&from_str(password))?;
    keys.reverse();

    let mut blocks = Vec::with_capacity(cipher.len());
    for i in 0..cipher.len() / 64 {
        let mut block = crypt_64(&cipher[64 * i..64 * i + 64], &keys)?;
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
    let mut keys = gen_keys(&from_str("passwort")).unwrap();
    let cipher = crypt_64(&from_str("hallo du"), &keys).unwrap();
    keys.reverse();
    let plaintext = crypt_64(&cipher, &keys).unwrap();
    assert_eq!(&plaintext, &from_str("hallo du"));

    let (cipher, space) = encrypt("Das hier ist ein Test", "8-bytes!").unwrap();
    let plaintext = decrypt(&cipher, "8-bytes!", space).unwrap();
    assert_eq!(&plaintext, "Das hier ist ein Test");
}

pub fn gen_keys(key: Bits) -> Result<Vec<OwnedBits>> {
    if key.len() != 64 {
        return Error::SizeError.into();
    }

    // pc-1 for key
    let (mut c, mut d) = permutate_choice1(key)?;

    // iterator for 16 rounds
    let mut keys = Vec::with_capacity(16);
    for i in 1..16 + 1 {
        // rotate key left
        rotate_left(&mut c);
        rotate_left(&mut d);

        // rotate key twice
        if i != 1 && i != 2 && i != 9 && i != 16 {
            rotate_left(&mut c);
            rotate_left(&mut d);
        }

        // key pc-2
        keys.push(permutate_choice2(&c, &d)?);
    }

    Ok(keys)
}

pub fn crypt_64(data: Bits, keys: &[OwnedBits]) -> Result<OwnedBits> {
    if keys.len() != 16 {
        return Error::SizeError.into();
    }

    // initial permutation
    let ip = permutate(data, IP_TABLE)?;

    // split data
    let (mut left, mut right) = split_owned(&ip);

    // iterator for 16 rounds
    for i in 1..16 + 1 {
        // encrypt round
        (left, right) = round(left, right, &keys[i - 1])?;
    }

    // final permutation
    let final_data = [right, left].concat();
    permutate(&final_data, FP_TABLE)
}

#[test]
fn test_crypt_64() {
    let keys = gen_keys(&[
        false, false, false, true, false, false, true, true, false, false, true, true, false, true,
        false, false, false, true, false, true, false, true, true, true, false, true, true, true,
        true, false, false, true, true, false, false, true, true, false, true, true, true, false,
        true, true, true, true, false, false, true, true, false, true, true, true, true, true,
        true, true, true, true, false, false, false, true,
    ])
    .unwrap();
    assert_eq!(
        &[
            true, false, false, false, false, true, false, true, true, true, true, false, true,
            false, false, false, false, false, false, true, false, false, true, true, false, true,
            false, true, false, true, false, false, false, false, false, false, true, true, true,
            true, false, false, false, false, true, false, true, false, true, false, true, true,
            false, true, false, false, false, false, false, false, false, true, false, true,
        ] as Bits,
        &crypt_64(
            &[
                false, false, false, false, false, false, false, true, false, false, true, false,
                false, false, true, true, false, true, false, false, false, true, false, true,
                false, true, true, false, false, true, true, true, true, false, false, false, true,
                false, false, true, true, false, true, false, true, false, true, true, true, true,
                false, false, true, true, false, true, true, true, true, false, true, true, true,
                true,
            ],
            &keys
        )
        .unwrap()
    );
}

fn round(mut left: OwnedBits, right: OwnedBits, key: Bits) -> Result<(OwnedBits, OwnedBits)> {
    let out = f(&right, key)?;
    xor(&mut left, &out)?;
    Ok((right, left))
}

#[test]
fn test_round() {
    assert_eq!(
        &[
            true, true, true, false, true, true, true, true, false, true, false, false, true,
            false, true, false, false, true, true, false, false, true, false, true, false, true,
            false, false, false, true, false, false,
        ] as Bits,
        &round(
            [
                true, true, false, false, true, true, false, false, false, false, false, false,
                false, false, false, false, true, true, false, false, true, true, false, false,
                true, true, true, true, true, true, true, true,
            ]
            .to_owned()
            .into(),
            [
                true, true, true, true, false, false, false, false, true, false, true, false, true,
                false, true, false, true, true, true, true, false, false, false, false, true,
                false, true, false, true, false, true, false,
            ]
            .to_owned()
            .into(),
            &[
                false, false, false, true, true, false, true, true, false, false, false, false,
                false, false, true, false, true, true, true, false, true, true, true, true, true,
                true, true, true, true, true, false, false, false, true, true, true, false, false,
                false, false, false, true, true, true, false, false, true, false,
            ] as Bits
        )
        .unwrap()
        .1
    )
}

fn f(right: Bits, key: Bits) -> Result<OwnedBits> {
    let mut data = expand(right)?;
    xor(&mut data, key)?;
    let sout = sbox(&data)?;
    permutate(&sout, P_TABLE)
}

#[test]
fn test_f() {
    assert_eq!(
        // output
        &[
            // 0010 0011 0100 1010 1010 1001 1011 1011
            false, false, true, false, false, false, true, true, false, true, false, false, true,
            false, true, false, true, false, true, false, true, false, false, true, true, false,
            true, true, true, false, true, true,
        ] as Bits,
        &f(
            // right
            &[
                // 0101 1100 1000 0010 1011 0101 1001 0111
                true, true, true, true, false, false, false, false, true, false, true, false, true,
                false, true, false, true, true, true, true, false, false, false, false, true,
                false, true, false, true, false, true, false,
            ],
            // key
            &[
                // 000110 110000 001011 101111 111111 000111 000001 110010
                false, false, false, true, true, false, true, true, false, false, false, false,
                false, false, true, false, true, true, true, false, true, true, true, true, true,
                true, true, true, true, true, false, false, false, true, true, true, false, false,
                false, false, false, true, true, true, false, false, true, false,
            ]
        )
        .unwrap()
    )
}

fn permutate(data: Bits, table: PermutationTable) -> Result<OwnedBits> {
    if data.len() != table.len() {
        return Error::SizeError.into();
    }

    let mut p = vec![false; data.len()];
    for i in 0..data.len() {
        p[i] = data[table[i] - 1];
    }

    Ok(p)
}

#[test]
fn test_permutate() {
    // IP
    assert_eq!(
        &[
            true, true, false, false, true, true, false, false, false, false, false, false, false,
            false, false, false, true, true, false, false, true, true, false, false, true, true,
            true, true, true, true, true, true, true, true, true, true, false, false, false, false,
            true, false, true, false, true, false, true, false, true, true, true, true, false,
            false, false, false, true, false, true, false, true, false, true, false,
        ] as Bits,
        &permutate(
            &[
                false, false, false, false, false, false, false, true, false, false, true, false,
                false, false, true, true, false, true, false, false, false, true, false, true,
                false, true, true, false, false, true, true, true, true, false, false, false, true,
                false, false, true, true, false, true, false, true, false, true, true, true, true,
                false, false, true, true, false, true, true, true, true, false, true, true, true,
                true,
            ],
            IP_TABLE
        )
        .unwrap()
    );

    // FP
    assert_eq!(
        &[
            false, false, false, false, false, false, false, true, false, false, true, false,
            false, false, true, true, false, true, false, false, false, true, false, true, false,
            true, true, false, false, true, true, true, true, false, false, false, true, false,
            false, true, true, false, true, false, true, false, true, true, true, true, false,
            false, true, true, false, true, true, true, true, false, true, true, true, true,
        ] as Bits,
        &permutate(
            &[
                true, true, false, false, true, true, false, false, false, false, false, false,
                false, false, false, false, true, true, false, false, true, true, false, false,
                true, true, true, true, true, true, true, true, true, true, true, true, false,
                false, false, false, true, false, true, false, true, false, true, false, true,
                true, true, true, false, false, false, false, true, false, true, false, true,
                false, true, false,
            ],
            FP_TABLE
        )
        .unwrap()
    );

    // P
    assert_eq!(
        &[
            false, false, true, false, false, false, true, true, false, true, false, false, true,
            false, true, false, true, false, true, false, true, false, false, true, true, false,
            true, true, true, false, true, true,
        ] as Bits,
        &permutate(
            &[
                false, true, false, true, true, true, false, false, true, false, false, false,
                false, false, true, false, true, false, true, true, false, true, false, true, true,
                false, false, true, false, true, true, true,
            ],
            P_TABLE
        )
        .unwrap()
    );
}

fn permutate_choice1(data: Bits) -> Result<(OwnedBits, OwnedBits)> {
    if data.len() != 64 {
        return Error::SizeError.into();
    }

    let mut p = vec![false; 56];
    for i in 0..56 {
        p[i] = data[PC1_TABLE[i] - 1];
    }

    Ok(split_owned(&p))
}

#[test]
fn test_permutate_choice1() {
    assert_eq!(
        &[
            false, false, false, true, true, false, true, true, false, false, false, false, false,
            false, true, false, true, true, true, false, true, true, true, true, true, true, true,
            true, true, true, false, false, false, true, true, true, false, false, false, false,
            false, true, true, true, false, false, true, false,
        ] as Bits,
        permutate_choice2(
            &[
                true, true, true, false, false, false, false, true, true, false, false, true, true,
                false, false, true, false, true, false, true, false, true, false, true, true, true,
                true, true,
            ],
            &[
                true, false, true, false, true, false, true, false, true, true, false, false, true,
                true, false, false, true, true, true, true, false, false, false, true, true, true,
                true, false,
            ]
        )
        .unwrap()
    )
}

fn permutate_choice2(c: Bits, d: Bits) -> Result<OwnedBits> {
    let key = [c, d].concat();
    if key.len() != 56 {
        return Error::SizeError.into();
    }

    let mut p = vec![false; 48];
    for i in 0..48 {
        p[i] = key[PC2_TABLE[i] - 1];
    }

    Ok(p)
}

#[test]
fn test_permutate_choice2() {
    assert_eq!(
        &[
            false, false, false, true, true, false, true, true, false, false, false, false, false,
            false, true, false, true, true, true, false, true, true, true, true, true, true, true,
            true, true, true, false, false, false, true, true, true, false, false, false, false,
            false, true, true, true, false, false, true, false,
        ] as Bits,
        permutate_choice2(
            &[
                true, true, true, false, false, false, false, true, true, false, false, true, true,
                false, false, true, false, true, false, true, false, true, false, true, true, true,
                true, true,
            ],
            &[
                true, false, true, false, true, false, true, false, true, true, false, false, true,
                true, false, false, true, true, true, true, false, false, false, true, true, true,
                true, false,
            ]
        )
        .unwrap()
    )
}

fn expand(data: Bits) -> Result<OwnedBits> {
    if data.len() != 32 {
        return Error::SizeError.into();
    }

    let mut e = vec![false; 48];
    for i in 0..48 {
        e[i] = data[E_TABLE[i] - 1];
    }

    Ok(e)
}

#[test]
fn test_expand() {
    assert_eq!(
        &[
            false, true, true, true, true, false, true, false, false, false, false, true, false,
            true, false, true, false, true, false, true, false, true, false, true, false, true,
            true, true, true, false, true, false, false, false, false, true, false, true, false,
            true, false, true, false, true, false, true, false, true,
        ] as Bits,
        &expand(&[
            true, true, true, true, false, false, false, false, true, false, true, false, true,
            false, true, false, true, true, true, true, false, false, false, false, true, false,
            true, false, true, false, true, false,
        ])
        .unwrap()
    )
}

fn distribute(data: Bits) -> Result<Bits8> {
    if data.len() != 48 {
        return Error::SizeError.into();
    }

    Ok((
        &data[0..6],
        &data[6..12],
        &data[12..18],
        &data[18..24],
        &data[24..30],
        &data[30..36],
        &data[36..42],
        &data[42..48],
    ))
}

#[test]
fn test_distribute() {
    assert_eq!(
        (
            &[false, true, true, false, false, false] as Bits,
            &[false, true, false, false, false, true] as Bits,
            &[false, true, true, true, true, false,] as Bits,
            &[true, true, true, false, true, false,] as Bits,
            &[true, false, false, false, false, true] as Bits,
            &[true, false, false, true, true, false] as Bits,
            &[false, true, false, true, false, false] as Bits,
            &[true, false, false, true, true, true] as Bits
        ),
        distribute(&[
            false, true, true, false, false, false, false, true, false, false, false, true, false,
            true, true, true, true, false, true, true, true, false, true, false, true, false,
            false, false, false, true, true, false, false, true, true, false, false, true, false,
            true, false, false, true, false, false, true, true, true
        ])
        .unwrap()
    );
}

fn substitute(data: Bits, table: SubstitutionTable) -> Result<OwnedBits> {
    if data.len() != 6 {
        return Error::SizeError.into();
    }

    let sub_table = match (data[0], data[5]) {
        (false, false) => table[0],
        (false, true) => table[1],
        (true, false) => table[2],
        (true, true) => table[3],
    };

    let mut value = to_bits(sub_table[to_u8(&data[1..5])? as usize] as u8);
    value.drain(0..4);
    Ok(value)
}

#[test]
fn test_substitute() {
    assert_eq!(
        &[false, true, false, true] as Bits,
        substitute(&[false, true, true, false, false, false], S1_TABLE).unwrap()
    );
}

fn sbox(data: Bits) -> Result<OwnedBits> {
    let distr = distribute(data)?;
    let mut res = Vec::with_capacity(32);
    res.append(&mut substitute(distr.0, S1_TABLE)?);
    res.append(&mut substitute(distr.1, S2_TABLE)?);
    res.append(&mut substitute(distr.2, S3_TABLE)?);
    res.append(&mut substitute(distr.3, S4_TABLE)?);
    res.append(&mut substitute(distr.4, S5_TABLE)?);
    res.append(&mut substitute(distr.5, S6_TABLE)?);
    res.append(&mut substitute(distr.6, S7_TABLE)?);
    res.append(&mut substitute(distr.7, S8_TABLE)?);

    Ok(res)
}

#[test]
fn test_sbox() {
    //rotate_left(data);
    assert_eq!(
        &[
            false, true, false, true, true, true, false, false, true, false, false, false, false,
            false, true, false, true, false, true, true, false, true, false, true, true, false,
            false, true, false, true, true, true,
        ] as Bits,
        &sbox(&[
            false, true, true, false, false, false, false, true, false, false, false, true, false,
            true, true, true, true, false, true, true, true, false, true, false, true, false,
            false, false, false, true, true, false, false, true, true, false, false, true, false,
            true, false, false, true, false, false, true, true, true,
        ])
        .unwrap()
    )
}

fn rotate_left(data: BitsMut) {
    let mut replaced = data[0];
    for i in (0..data.len()).rev() {
        swap(&mut data[i], &mut replaced);
    }
}

#[test]
fn test_rotate_left() {
    let data: BitsMut = &mut [
        true, true, false, false, false, true, false, true, false, false, false, true, false, true,
        true, true, false, true, false, false, false, false, false, true, false, true,
    ];
    rotate_left(data);
    assert_eq!(
        &[
            true, false, false, false, true, false, true, false, false, false, true, false, true,
            true, true, false, true, false, false, false, false, false, true, false, true, true
        ] as Bits,
        data
    );

    let d0: BitsMut = &mut [
        false, true, false, true, false, true, false, true, false, true, true, false, false, true,
        true, false, false, true, true, true, true, false, false, false, true, true, true, true,
    ];
    rotate_left(d0);
    assert_eq!(
        &[
            true, false, true, false, true, false, true, false, true, true, false, false, true,
            true, false, false, true, true, true, true, false, false, false, true, true, true,
            true, false,
        ],
        d0 // rotated
    );
}

/*
fn rotate_right(data: BitsMut) {
    let mut replaced = data[data.len() - 1];
    for i in 0..data.len() {
        let temp = data[i];
        data[i] = replaced;
        replaced = temp;
    }
}

#[test]
fn test_rotate_right() {
    let data: BitsMut = &mut [
        true, false, false, false, true, false, true, false, false, false, true, false, true, true,
        true, false, true, false, false, false, false, false, true, false, true, true,
    ];
    rotate_right(data);
    assert_eq!(
        &[
            true, true, false, false, false, true, false, true, false, false, false, true, false,
            true, true, true, false, true, false, false, false, false, false, true, false, true,
        ] as Bits,
        data
    );

    let d0: BitsMut = &mut [
        true, false, true, false, true, false, true, false, true, true, false, false, true, true,
        false, false, true, true, true, true, false, false, false, true, true, true, true, false,
    ];
    rotate_right(d0);
    assert_eq!(
        &[
            false, true, false, true, false, true, false, true, false, true, true, false, false,
            true, true, false, false, true, true, true, true, false, false, false, true, true,
            true, true,
        ],
        d0 // rotated
    );
}
*/
