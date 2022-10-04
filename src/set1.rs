use std::collections::HashMap;

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};

use crate::util::hamming_distance;

// TODO: Get rid of this and just have functions return the key. This doesn't really scale for
// large ciphertexts, or for ones that aren't encoded.
#[derive(Clone)]
pub struct Candidate {
    pub rating: f32,
    pub key: u8,
    pub encrypted: String,
    pub plaintext: String,
}

pub fn xor_buffers(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|p| p.0 ^ p.1).collect()
}

// XOR each element of the specified slice with the specified key.
pub fn xor_vec(v: &[u8], key: u8) -> Vec<u8> {
    v.iter().map(|b| b ^ key).collect::<Vec<u8>>()
}

// Sequentially XOR each element of the specified slice with the corresponding element of the
// specified key, cycling back to the beginning once exhausted.
pub fn repeating_key_xor_vec(v: &[u8], key: &[u8]) -> Vec<u8> {
    v.iter()
        .zip(key.iter().cycle())
        .map(|e| e.0 ^ e.1)
        .collect::<Vec<u8>>()
}

pub fn english_rating(frequencies: &HashMap<char, f32>, s: &str) -> f32 {
    let trimmed = s.trim();

    let mut counts: HashMap<char, f32> = HashMap::new();
    trimmed
        .chars()
        .map(|c| c.to_ascii_uppercase())
        .for_each(|item| *counts.entry(item).or_default() += 1.0);

    let mut coefficient: f32 = 0.0;
    for count in counts {
        if let Some(freq) = frequencies.get(&count.0) {
            coefficient += f32::sqrt(freq * count.1 / (trimmed.len() as f32));
        }
    }

    coefficient
}

// TODO: Separate out the hex decoding and decrypting
pub fn detect_single_byte_xor_key(hex: &str) -> Option<Candidate> {
    let bytes = crate::encodings::hex_decode(hex);
    let mut candidates: Vec<Candidate> = Vec::new();

    #[allow(clippy::approx_constant)]
    let frequencies = HashMap::from([
        ('E', 12.02),
        ('T', 9.10),
        ('A', 8.12),
        ('O', 7.68),
        ('I', 7.31),
        ('N', 6.95),
        ('S', 6.28),
        ('R', 6.02),
        ('H', 5.92),
        ('D', 4.32),
        ('L', 3.98),
        ('U', 2.88),
        ('C', 2.71),
        ('M', 2.61),
        ('F', 2.30),
        ('Y', 2.11),
        ('W', 2.09),
        ('G', 2.03),
        ('P', 1.82),
        ('B', 1.49),
        ('V', 1.11),
        ('K', 0.69),
        ('X', 0.17),
        ('Q', 0.11),
        ('J', 0.10),
        ('Z', 0.07),
        (' ', 0.19),
    ]);

    for key in 0x00..0xFF_u8 {
        if !key.is_ascii() {
            continue;
        }
        // TODO: Separate out the xoring function
        let xored = xor_vec(&bytes, key);
        if let Ok(s) = std::str::from_utf8(&xored) {
            let rating = english_rating(&frequencies, s);
            candidates.push(Candidate {
                rating,
                key,
                encrypted: hex.to_string(),
                plaintext: s.to_string(),
            });
        }
    }

    candidates.sort_by(|a, b| a.rating.partial_cmp(&b.rating).unwrap());
    candidates.last().cloned()
}

pub fn find_xored_string(strings: &Vec<&str>) -> Option<Candidate> {
    let mut candidates: Vec<Candidate> = Vec::new();

    for s in strings {
        if let Some(candidate) = detect_single_byte_xor_key(*s) {
            candidates.push(candidate);
        }
    }

    candidates.sort_by(|a, b| a.rating.partial_cmp(&b.rating).unwrap());
    candidates.last().cloned()
}

fn find_keysize_simple(encrypted: &[u8]) -> u8 {
    let mut keysize_distance: Option<(u8, f64)> = None;
    for keysize in 2..=40 {
        let mut blocks = encrypted.chunks(keysize);
        let block1 = blocks.next().unwrap();
        let block2 = blocks.next().unwrap();

        let normalizd_distance = hamming_distance(&block1, &block2) as f64 / keysize as f64;
        if let Some((_, distance)) = keysize_distance {
            if normalizd_distance < distance {
                keysize_distance = Some((keysize as u8, normalizd_distance));
            }
        } else {
            keysize_distance = Some((keysize as u8, normalizd_distance));
        }
    }
    keysize_distance.unwrap().0
}

fn find_keysize_average(encrypted: &[u8]) -> u8 {
    let mut keysize_distance: Option<(u8, f64)> = None;
    for keysize in 2..=40 {
        let mut blocks = encrypted.chunks(keysize);
        let block1 = blocks.next().unwrap();
        let block2 = blocks.next().unwrap();
        let block3 = blocks.next().unwrap();
        let block4 = blocks.next().unwrap();

        let mut normalizd_distances: Vec<f64> = Vec::new();
        normalizd_distances.push(hamming_distance(&block1, &block2) as f64 / keysize as f64);
        normalizd_distances.push(hamming_distance(&block1, &block3) as f64 / keysize as f64);
        normalizd_distances.push(hamming_distance(&block1, &block4) as f64 / keysize as f64);
        normalizd_distances.push(hamming_distance(&block2, &block3) as f64 / keysize as f64);
        normalizd_distances.push(hamming_distance(&block2, &block4) as f64 / keysize as f64);
        normalizd_distances.push(hamming_distance(&block3, &block4) as f64 / keysize as f64);

        let mut average_distance: f64 = normalizd_distances.iter().sum();
        average_distance = average_distance / normalizd_distances.len() as f64;
        if let Some((_, distance)) = keysize_distance {
            if average_distance < distance {
                keysize_distance = Some((keysize as u8, average_distance));
            }
        } else {
            keysize_distance = Some((keysize as u8, average_distance));
        }
    }

    keysize_distance.unwrap().0
}

pub fn find_repeating_key_xored_string(encrypted: &[u8]) -> String {
    let keysize = find_keysize_average(encrypted);
    let transposed = crate::util::transpose(encrypted, keysize as usize);
    let mut key = String::new();
    for block in transposed {
        let hex = crate::encodings::hex_encode(&block);
        if let Some(best_candidate) = detect_single_byte_xor_key(&hex) {
            key.push(best_candidate.key as char);
        }
    }
    key
}

pub fn decrypt_aes128(encrypted: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key);
    let cipher = aes::Aes128::new(&key);
    let chunks = encrypted.chunks(16);
    let mut blocks = Vec::new();
    for chunk in chunks {
        blocks.push(GenericArray::clone_from_slice(chunk));
    }
    cipher.decrypt_blocks(&mut blocks);

    blocks.iter().flatten().copied().collect()
}

#[cfg(test)]
mod test {
    use super::decrypt_aes128;

    #[test]
    fn xor_vec_zero() {
        let bytes = [0, 1, 2, 3, 4];
        assert_eq!(crate::set1::xor_vec(&bytes, 0), bytes);
    }

    #[test]
    fn xor_vec_ff() {
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(crate::set1::xor_vec(&bytes, 0xFF), [0, 0, 0, 0, 0]);
    }

    #[test]
    fn challenge1() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let bytes = crate::encodings::hex_decode(&hex);
        let base64 = crate::encodings::base64_encode(&bytes);
        assert_eq!(
            base64,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn challenge2() {
        let a = "1c0111001f010100061a024b53535009181c";
        let b = "686974207468652062756c6c277320657965";
        let xored = crate::set1::xor_buffers(
            &crate::encodings::hex_decode(a),
            &crate::encodings::hex_decode(b),
        );
        assert_eq!(
            "746865206b696420646f6e277420706c6179",
            crate::encodings::hex_encode(&xored)
        );
    }

    #[test]
    fn challenge3() {
        let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let best_candidate = crate::set1::detect_single_byte_xor_key(&hex).unwrap();
        assert_eq!(0x58, best_candidate.key);
        assert_eq!(
            "Cooking MC's like a pound of bacon",
            best_candidate.plaintext
        )
    }

    #[test]
    fn challenge4() {
        let file_contents =
            std::fs::read_to_string("data/4.txt").expect("Failed to read XORed strings");
        let xored_strings = file_contents.split_whitespace().collect::<Vec<&str>>();
        let best_candidate = crate::set1::find_xored_string(&xored_strings).unwrap();
        assert_eq!(0x35, best_candidate.key);
        assert_eq!("Now that the party is jumping\n", best_candidate.plaintext);
    }

    #[test]
    fn challenge5() {
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let xored = crate::set1::repeating_key_xor_vec(plaintext.as_bytes(), "ICE".as_bytes());
        let hex = crate::encodings::hex_encode(&xored);
        assert_eq!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", hex);
    }

    #[test]
    fn challenge6() {
        let base64 = std::fs::read_to_string("data/6.txt").unwrap();
        let bytes = crate::encodings::base64_decode(&base64).unwrap();
        let key = crate::set1::find_repeating_key_xored_string(&bytes);
        assert_eq!("Terminator X: Bring the noise", key);
    }

    #[test]
    fn challenge7() {
        let base64 = std::fs::read_to_string("data/7.txt").unwrap();
        let bytes = crate::encodings::base64_decode(&base64).unwrap();
        let decrypted = decrypt_aes128(&bytes, "YELLOW SUBMARINE".as_bytes());
        let plaintext = std::str::from_utf8(&decrypted).unwrap();
        assert!(plaintext.starts_with("I'm back and I'm ringin' the bell"));
    }
}
