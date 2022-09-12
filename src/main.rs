fn hex_to_bytes(hex: &str) -> Vec<u8> {
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

fn bytes_to_base64(bytes: &[u8]) -> String {
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

fn main() {
    let s = std::env::args()
        .nth(1)
        .expect("Failed to retrieve first argument");
    println!("hex: {}", s);

    let bytes = hex_to_bytes(&s);
    println!("bytes: {:?}", bytes);

    let base64 = bytes_to_base64(&bytes);
    println!("base64: {}", base64);
}
