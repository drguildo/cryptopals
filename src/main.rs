fn main() {
    let s = std::env::args()
        .nth(1)
        .expect("Failed to retrieve first argument");
    println!("hex: {}", s);

    let bytes = cryptopals::set1::hex_to_bytes(&s);
    println!("bytes: {:?}", bytes);

    let base64 = cryptopals::set1::bytes_to_base64(&bytes);
    println!("base64: {}", base64);
}
