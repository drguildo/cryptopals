use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

use crate::util::{pkcs7_pad, pkcs7_unpad};

pub fn encrypt_aes128_cbc(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    pkcs7_pad(&mut bytes, 16);

    let key = GenericArray::clone_from_slice(key);
    let cipher = aes::Aes128::new(&key);

    let chunks: Vec<&[u8]> = bytes.chunks(16).collect();
    let mut encrypted_blocks: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    while i < chunks.len() {
        let mut block = GenericArray::clone_from_slice(chunks[i]);
        if i > 0 {
            // XOR current plaintext block with previous encrypted block.
            let previous_block = &encrypted_blocks[i - 1];
            let xored = crate::util::xor_buffers(&block, &previous_block);
            block = GenericArray::clone_from_slice(&xored);
        }
        cipher.encrypt_block(&mut block);
        encrypted_blocks.push(block.to_vec());
        i += 1;
    }

    encrypted_blocks.iter().flatten().copied().collect()
}

pub fn decrypt_aes128_cbc(encrypted: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key);
    let cipher = aes::Aes128::new(&key);

    let chunks: Vec<&[u8]> = encrypted.chunks(16).collect();
    let mut decrypted_blocks = Vec::new();
    let mut i = chunks.len() - 1;
    while i > 0 {
        let mut block = GenericArray::clone_from_slice(chunks[i]);
        // Decrypt the block.
        cipher.decrypt_block(&mut block);
        // XOR the decrypted chunk with the preceding, encrypted block.
        let previous_block = chunks[i - 1];
        let xored_block = crate::util::xor_buffers(&block, previous_block);
        decrypted_blocks.push(xored_block);
        i -= 1;
    }

    if i == 0 {
        let mut block = GenericArray::clone_from_slice(chunks[i]);
        cipher.decrypt_block(&mut block);
        // First block isn't XORed with anything.
        decrypted_blocks.push(block.to_vec());
    }

    decrypted_blocks.reverse();
    let mut decrypted_bytes = decrypted_blocks.iter().flatten().copied().collect();
    pkcs7_unpad(&mut decrypted_bytes);
    decrypted_bytes
}

#[cfg(test)]
mod test {
    use super::{decrypt_aes128_cbc, encrypt_aes128_cbc};

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
        let encrypted = encrypt_aes128_cbc(plaintext, key);
        let decrypted = decrypt_aes128_cbc(&encrypted, key);
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn challenge10_decrypt() {
        let file_contents = std::fs::read_to_string("data/10.txt").unwrap();
        let decoded = crate::encodings::base64_decode(&file_contents).unwrap();
        let decrypted = decrypt_aes128_cbc(&decoded, "YELLOW SUBMARINE".as_bytes());
        let plaintext = std::str::from_utf8(&decrypted).unwrap();
        assert!(plaintext.starts_with("I'm back and I'm ringin' the bell"));
    }
}
