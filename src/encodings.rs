pub fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

pub fn hex_decode(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut digits = String::new();
    for (i, c) in hex.chars().enumerate() {
        if c.is_ascii_control() {
            continue;
        }
        digits.push(c);
        if (i == hex.len() - 1) || digits.len() == 2 {
            let b = u8::from_str_radix(&digits, 16).expect("Invalid hex string");
            bytes.push(b);
            digits = String::new();
        }
    }
    bytes
}

const ALPHABET: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

pub fn base64_encode(bytes: &[u8]) -> String {
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

        s.push(ALPHABET[(u >> 18) as usize]);
        s.push(ALPHABET[((u >> 12) & 63) as usize]);
        s.push(if read < 2 {
            '='
        } else {
            ALPHABET[(u >> 6 & 63) as usize]
        });
        s.push(if read < 3 {
            '='
        } else {
            ALPHABET[(u & 63) as usize]
        });
    }

    s
}

fn find_index(c: char) -> Result<u8, &'static str> {
    let ascii = c as u8;
    match c {
        'A'..='Z' => Ok(ascii - ('A' as u8)),
        'a'..='z' => Ok(ascii - ('a' as u8) + 26),
        '0'..='9' => Ok(ascii - ('0' as u8) + 52),
        '+' => Ok(62),
        '/' => Ok(63),
        _ => Err("Invalid Base64 character"),
    }
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let chars = s
        .chars()
        .filter(|c| !c.is_ascii_control())
        .collect::<Vec<char>>();
    if (chars.len() % 4) != 0 {
        return Err("Invalid Base64 string length");
    }

    let mut acc: u8;
    let mut decoded = Vec::new();
        let mut i = 0;
    while i < chars.len() {
        let b1 = chars[i];
        let b2 = chars[i + 1];
        let b3 = chars[i + 2];
        let b4 = chars[i + 3];
        i += 4;

        let i1 = find_index(b1)?;
        let i2 = find_index(b2)?;

        acc = i1 << 2;
        acc |= i2 >> 4;
        decoded.push(acc);

        if b3 != '=' {
            let i3 = find_index(b3)?;

            acc = (i2 & 0xF) << 4;
            acc += i3 >> 2; // Should this be an &=?
            decoded.push(acc);

            if b4 != '=' {
                let i4 = find_index(b4)?;

                acc = (i3 & 0x3) << 6;
                acc |= i4;
                decoded.push(acc);
            }
        }
    }

    Ok(decoded)
}

mod test {
    #[test]
    fn hex_encode_byte_array() {
        let bytes = [
            116, 104, 101, 32, 107, 105, 100, 32, 100, 111, 110, 39, 116, 32, 112, 108, 97, 121,
        ];
        assert_eq!(
            crate::encodings::hex_encode(&bytes),
            "746865206b696420646f6e277420706c6179"
        );
    }

    #[test]
    fn decode_hex_string() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let decoded_bytes = crate::encodings::hex_decode(hex);
        let decoded_string = std::str::from_utf8(&decoded_bytes).unwrap();
        assert_eq!(
            decoded_string,
            "I'm killing your brain like a poisonous mushroom"
        );
    }

    #[test]
    fn decode_hex_string_with_newline() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f757320\n6d757368726f6f6d";
        let decoded_bytes = crate::encodings::hex_decode(hex);
        let decoded_string = std::str::from_utf8(&decoded_bytes).unwrap();
        assert_eq!(
            decoded_string,
            "I'm killing your brain like a poisonous mushroom"
        );
    }

    #[test]
    fn decode_short_base64_string() {
        let base64 = "bGlnaHQgd29yay4=";
        let decoded_bytes = crate::encodings::base64_decode(base64).unwrap();
        let decoded_string = std::str::from_utf8(&decoded_bytes).unwrap();
        assert_eq!("light work.", decoded_string);
    }

    #[test]
    fn decode_empty_base64_string() {
        let decoded_bytes = crate::encodings::base64_decode("").unwrap();
        assert_eq!(Vec::<u8>::new(), decoded_bytes);
    }

    #[test]
    fn decode_base64_string_with_newline() {
        let base64 = "IlVzZSB0aGUgZm9yY2UsIEhh\ncnJ5ISIgLSBHYW5kYWxm";
        let decoded_bytes = crate::encodings::base64_decode(base64).unwrap();
        let decoded_string = std::str::from_utf8(&decoded_bytes).unwrap();
        assert_eq!("\"Use the force, Harry!\" - Gandalf", decoded_string);
    }

    #[test]
    fn encode_and_decode_matches_original() {
        let bytes = [1, 2, 3, 4, 5, 6];
        let encoded = crate::encodings::base64_encode(&bytes);
        let decoded = crate::encodings::base64_decode(&encoded).unwrap();
        assert_eq!(bytes, decoded.as_slice());
    }
}
