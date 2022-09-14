use cryptopals::set1::{bytes_to_hex, hex_to_bytes, xor_buffers};

fn main() {
    let bytes_a = hex_to_bytes("1c0111001f010100061a024b53535009181c");
    let bytes_b = hex_to_bytes("686974207468652062756c6c277320657965");
    let xored_bytes = xor_buffers(&bytes_a, &bytes_b);
    println!("{}", bytes_to_hex(&xored_bytes));
}
