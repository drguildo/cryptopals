fn main() {
    let base64 = std::fs::read_to_string("data/6.txt").unwrap();
    let bytes = cryptopals::encodings::base64_decode(&base64).unwrap();
    cryptopals::set1::find_repeating_key_xored_string(&bytes);
}
