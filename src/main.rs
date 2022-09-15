use cryptopals::set1::single_byte_xor_cypher;

fn main() {
    println!("== Set 1, Challenge 3 ==");
    let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    if let Some(key) = single_byte_xor_cypher(&hex) {
        let bytes = cryptopals::set1::hex_to_bytes(&hex);
        let xored = bytes.iter().map(|b| b ^ key).collect::<Vec<u8>>();
        let plaintext = std::str::from_utf8(&xored).expect("Decrypted text is not valid UTF-8");
        println!("key: {:#X}, text: {}", key, plaintext);
    }
}
