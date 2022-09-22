use std::collections::HashMap;

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
        .map(|b| format!("{:02x}", b).to_string())
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
        u = u | ((c[1] as u64) << 8);
        u = u | (c[2] as u64);

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

// XOR each element of the specified Vec with the specified key.
pub fn xor_vec(v: &[u8], key: u8) -> Vec<u8> {
    v.iter().map(|b| b ^ key).collect::<Vec<u8>>()
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

pub fn single_byte_xor_cypher(hex: &str) -> Option<(f32, u8)> {
    let bytes = hex_to_bytes(&hex);
    let mut candidates: Vec<(f32, u8)> = Vec::new();

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
            candidates.push((rating, key));
        }
    }

    candidates.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    candidates.last().map(|c| c.to_owned())
}

pub fn find_xored_string(strings: &Vec<&str>) -> Option<String> {
    let mut best_candidate_key: Option<(f32, u8)> = None;
    let mut best_candidate_text: Option<&str> = None;

    for s in strings {
        if let Some(candidate) = single_byte_xor_cypher(*s) {
            if let Some(best) = best_candidate_key {
                if candidate.0 > best.0 {
                    best_candidate_key = Some(candidate);
                    best_candidate_text = Some(*s);
                }
            } else {
                best_candidate_key = Some(candidate);
                best_candidate_text = Some(*s);
            }
        }
    }

    if let Some(s) = best_candidate_text {
        if let Some(candidate) = best_candidate_key {
            let bytes = hex_to_bytes(s);
            let xored = xor_vec(&bytes, candidate.1);
            let plaintext = std::str::from_utf8(&xored).expect("Decrypted text is not valid UTF-8");
            Some(plaintext.to_owned())
        } else {
            None
        }
    } else {
        None
    }
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
}
