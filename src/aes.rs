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

// TODO: Add an encrypt function?
pub fn decrypt_aes128_ecb(encrypted: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key);
    let cipher = aes::Aes128::new(&key);
    let chunks = encrypted.chunks(16);
    let mut blocks = Vec::new();
    for chunk in chunks {
        blocks.push(GenericArray::clone_from_slice(chunk));
    }
    cipher.decrypt_blocks(&mut blocks);

    blocks.iter().flatten().copied().collect()
}

pub fn detect_aes128_ecb(strings: &[&str]) -> String {
    let mut average_distances: Vec<(u32, String)> = Vec::new();
    for s in strings {
        let decoded = crate::encodings::hex_decode(s);
        let chunks: Vec<&[u8]> = decoded.chunks(16).collect();

        let mut total_distances = 0;
        for i in 0..chunks.len() {
            for j in i + 1..chunks.len() {
                let distance = crate::util::hamming_distance(chunks[i], chunks[j]);
                total_distances += distance;
            }
        }
        average_distances.push((total_distances / (chunks.len() as u32), s.to_string()));
    }
    average_distances.sort_by(|a, b| a.0.cmp(&b.0));
    average_distances.first().unwrap().1.clone()
}
