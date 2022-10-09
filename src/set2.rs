use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

use crate::util::pkcs7_pad;

pub fn encrypt_aes128_cbc(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key);
    let cipher = aes::Aes128::new(&key);

    let mut chunks: Vec<&[u8]> = bytes.chunks(16).collect();
    let padded: Vec<u8>;
    if let Some(last_chunk) = chunks.last() {
        if last_chunk.len() < 16 {
            // If last block isn't the correct length, pad it.
            padded = pkcs7_pad(last_chunk, 16);
            chunks.remove(chunks.len() - 1);
            chunks.push(&padded);
        } else if last_chunk.len() == 16 {
            // Last block doesn't need to be padded, so add an extra padding block.
            padded = [16; 16].to_vec();
            chunks.remove(chunks.len() - 1);
            chunks.push(&padded);
        }
    }
    let mut encrypted_blocks: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    while i < chunks.len() {
        let mut block = GenericArray::clone_from_slice(chunks[i]);
        if i > 0 {
            // XOR current plaintext block with previous encrypted block.
            let previous_block = encrypted_blocks[i - 1].clone();
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
        if i == chunks.len() - 1 {
            // Remove padding from last block.
            let unpadded_block = crate::util::pkcs7_unpad(&xored_block);
            decrypted_blocks.push(unpadded_block);
        } else {
            decrypted_blocks.push(xored_block);
        }
        i -= 1;
    }

    if i == 0 {
        let mut block = GenericArray::clone_from_slice(chunks[i]);
        cipher.decrypt_block(&mut block);
        // First block isn't XORed with anything.
        decrypted_blocks.push(block.to_vec());
    }

    decrypted_blocks.reverse();
    decrypted_blocks.iter().flatten().copied().collect()
}

#[cfg(test)]
mod test {
    use super::{decrypt_aes128_cbc, encrypt_aes128_cbc};

    #[test]
    fn challenge9() {
        let padded = crate::util::pkcs7_pad("YELLOW SUBMARINE".as_bytes(), 20);
        assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(), padded);
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
