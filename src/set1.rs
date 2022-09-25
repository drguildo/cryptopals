use std::collections::HashMap;

#[derive(Clone)]
pub struct Candidate {
    pub rating: f32,
    pub key: u8,
    pub encrypted: String,
    pub plaintext: String,
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut i = 0;
    while i < hex.len() {
        let n = if i <= hex.len() - 2 {
            &hex[i..i + 2]
        } else {
            &hex[i..i + 1]
        };
        let b = u8::from_str_radix(n, 16).expect("Invalid hex string");
        bytes.push(b);
        i += 2;
    }
    bytes
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

pub fn bytes_to_base64(bytes: &[u8]) -> String {
    let alpha = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    ];

    let mut s = String::new();
    let mut c = [0; 3];
    let mut i: usize = 0;
    let mut u: u64;
    let mut read;

    while i < bytes.len() {
        c[1] = 0;
        c[2] = 0;

        c[0] = bytes[i];
        i += 1;
        read = 1;

        if i < bytes.len() {
            c[1] = bytes[i];
            i += 1;
            read = 2;

            if i < bytes.len() {
                c[2] = bytes[i];
                i += 1;
                read = 3;
            }
        }

        u = (c[0] as u64) << 16;
        u |= (c[1] as u64) << 8;
        u |= c[2] as u64;

        s.push(alpha[(u >> 18) as usize]);
        s.push(alpha[((u >> 12) & 63) as usize]);
        s.push(if read < 2 {
            '='
        } else {
            alpha[(u >> 6 & 63) as usize]
        });
        s.push(if read < 3 {
            '='
        } else {
            alpha[(u & 63) as usize]
        });
    }

    s
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

pub fn detect_single_byte_xor_key(hex: &str) -> Option<Candidate> {
    let bytes = hex_to_bytes(hex);
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

// Find the Hamming distance between the specified strings.
pub fn hamming_distance(s1: &str, s2: &str) -> u32 {
    s1.bytes()
        .zip(s2.bytes())
        .map(|e| (e.0 ^ e.1).count_ones())
        .fold(0, |acc, x| acc + x)
}

#[cfg(test)]
mod test {
    #[test]
    fn hex_to_base64() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let bytes = crate::set1::hex_to_bytes(&hex);
        assert_eq!(crate::set1::bytes_to_base64(&bytes), base64);
    }

    #[test]
    fn bytes_to_hex() {
        let bytes = [
            116, 104, 101, 32, 107, 105, 100, 32, 100, 111, 110, 39, 116, 32, 112, 108, 97, 121,
        ];
        assert_eq!(
            crate::set1::bytes_to_hex(&bytes),
            "746865206b696420646f6e277420706c6179"
        );
    }

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
        let bytes = crate::set1::hex_to_bytes(&hex);
        let base64 = crate::set1::bytes_to_base64(&bytes);
        assert_eq!(
            base64,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn challenge2() {
        let a = "1c0111001f010100061a024b53535009181c";
        let b = "686974207468652062756c6c277320657965";
        let xored =
            crate::set1::xor_buffers(&crate::set1::hex_to_bytes(a), &crate::set1::hex_to_bytes(b));
        assert_eq!(
            "746865206b696420646f6e277420706c6179",
            crate::set1::bytes_to_hex(&xored)
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
        let hex = crate::set1::bytes_to_hex(&xored);
        assert_eq!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", hex);
    }

    #[test]
    fn hamming_distance_37() {
        assert_eq!(
            crate::set1::hamming_distance("this is a test", "wokka wokka!!!"),
            37
        );
    }
}
