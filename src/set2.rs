#[cfg(test)]
mod test {
    #[test]
    fn challenge9() {
        let mut bytes = "YELLOW SUBMARINE".as_bytes().to_vec();
        crate::util::pkcs7_pad(&mut bytes, 20);
        assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(), bytes);
    }

    #[test]
    fn challenge10_encrypt() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let plaintext = "I'm back and I'm ringin' the bell".as_bytes();
        let encrypted = crate::aes::encrypt_aes128_cbc(plaintext, key);
        let decrypted = crate::aes::decrypt_aes128_cbc(&encrypted, key);
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn challenge10_decrypt() {
        let file_contents = std::fs::read_to_string("data/10.txt").unwrap();
        let decoded = crate::encodings::base64_decode(&file_contents).unwrap();
        let decrypted = crate::aes::decrypt_aes128_cbc(&decoded, "YELLOW SUBMARINE".as_bytes());
        let plaintext = std::str::from_utf8(&decrypted).unwrap();
        assert!(plaintext.starts_with("I'm back and I'm ringin' the bell"));
    }
}
