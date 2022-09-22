use cryptopals::set1::hex_to_bytes;

fn main() {
    println!("== Set 1, Challenge 1 ==");
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let bytes = cryptopals::set1::hex_to_bytes(&hex);
    let base64 = cryptopals::set1::bytes_to_base64(&bytes);
    println!("{} = {}", hex, base64);

    println!("== Set 1, Challenge 2 ==");
    let a = "1c0111001f010100061a024b53535009181c";
    let b = "686974207468652062756c6c277320657965";
    let xored = cryptopals::set1::xor_buffers(&hex_to_bytes(a), &hex_to_bytes(b));
    println!("{} ^ {} = {}", a, b, cryptopals::set1::bytes_to_hex(&xored));

    println!("== Set 1, Challenge 3 ==");
    let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    if let Some(candidate_key) = cryptopals::set1::single_byte_xor_cypher(&hex) {
        let bytes = cryptopals::set1::hex_to_bytes(&hex);
        let xored = cryptopals::set1::xor_vec(&bytes, candidate_key.1);
        let plaintext = std::str::from_utf8(&xored).expect("Decrypted text is not valid UTF-8");
        println!(
            "key: {:#X}, rating: {}, text: {}",
            candidate_key.1, candidate_key.0, plaintext
        );
    }

    println!("== Set 1, Challenge 4 ==");
    let file_contents =
        std::fs::read_to_string("data/4.txt").expect("Failed to read xored strings");
    let xored_strings = file_contents.split_whitespace().collect::<Vec<&str>>();
    let best_candidate = cryptopals::set1::find_xored_string(&xored_strings);
    print!("{}", best_candidate.unwrap());
}
