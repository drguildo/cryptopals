pub fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

pub fn hex_decode(hex: &str) -> Vec<u8> {
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

pub fn base64_encode(bytes: &[u8]) -> String {
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

mod test {
    #[test]
    fn hex_to_base64() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let bytes = crate::encodings::hex_decode(&hex);
        assert_eq!(crate::encodings::base64_encode(&bytes), base64);
    }

    #[test]
    fn bytes_to_hex() {
        let bytes = [
            116, 104, 101, 32, 107, 105, 100, 32, 100, 111, 110, 39, 116, 32, 112, 108, 97, 121,
        ];
        assert_eq!(
            crate::encodings::hex_encode(&bytes),
            "746865206b696420646f6e277420706c6179"
        );
    }
}
