use rand::Rng;

// Find the Hamming distance between the specified slices.
pub fn hamming_distance(s1: &[u8], s2: &[u8]) -> u32 {
    s1.iter()
        .zip(s2.iter())
        .map(|e| (e.0 ^ e.1).count_ones())
        .fold(0, |acc, x| acc + x)
}

// TODO: Make this more declarative/functional
pub fn transpose(bytes: &[u8], block_size: usize) -> Vec<Vec<u8>> {
    let chunks = bytes.chunks(block_size);
    let mut transposed: Vec<Vec<u8>> = Vec::new();
    for chunk in chunks {
        for i in 0..block_size {
            if i < chunk.len() {
                if let Some(block) = transposed.get_mut(i) {
                    block.push(chunk[i]);
                } else {
                    let mut block = Vec::new();
                    block.push(chunk[i]);
                    transposed.insert(i, block);
                }
            }
        }
    }
    transposed
}

// XOR the contents of one slice with the contents of another.
pub fn xor_buffers(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|p| p.0 ^ p.1).collect()
}

// XOR each element of the specified slice with the specified key.
pub fn xor_vec(v: &[u8], key: u8) -> Vec<u8> {
    v.iter().map(|b| b ^ key).collect::<Vec<u8>>()
}

// Pad the specified data using PKCS #7.
pub fn pkcs7_pad(bytes: &mut Vec<u8>, block_length: u8) {
    if bytes.len() == 0 {
        return;
    }

    let padding: Vec<u8>;
    let modulo = bytes.len() % (block_length as usize);
    if modulo == 0 {
        padding = vec![block_length; block_length as usize];
    } else {
        let num_padding_bytes = block_length - (modulo as u8);
        padding = vec![num_padding_bytes as u8; num_padding_bytes as usize];
    }
    bytes.extend_from_slice(&padding);
}

pub fn pkcs7_unpad(bytes: &mut Vec<u8>) {
    if let Some(padding_length) = bytes.iter().last() {
        let mut num_to_remove = padding_length.clone();
        while num_to_remove > 0 {
            bytes.pop().expect("Vec should not be empty");
            num_to_remove -= 1;
        }
    }
}

/// Generate a random AES-128 key.
pub fn random_key() -> [u8; 16] {
    let mut key = [0; 16];
    for i in 0..key.len() {
        key[i] = rand::random();
    }
    key
}

/// Add a random number of bytes between 5-10 (inclusive)
pub fn encryption_oracle(bytes: &[u8]) -> Vec<u8> {
    let key = random_key();
    let mut padded_bytes = Vec::new();
    for _i in 0..rand::thread_rng().gen_range(5..=10) {
        padded_bytes.push(rand::random());
    }
    padded_bytes.extend_from_slice(bytes);
    for _i in 0..rand::thread_rng().gen_range(5..=10) {
        padded_bytes.push(rand::random());
    }
    let encrypted = if rand::random() {
        crate::aes::encrypt_aes128_cbc(&padded_bytes, &key)
    } else {
        crate::aes::encrypt_aes128_ecb(&padded_bytes, &key)
    };
    encrypted
}

#[cfg(test)]
mod test {
    #[test]
    fn hamming_distance_37() {
        assert_eq!(
            crate::util::hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()),
            37
        );
    }

    #[test]
    fn transpose_empty() {
        let transposed = crate::util::transpose(&[], 4);
        assert!(transposed.is_empty());
    }

    #[test]
    fn transpose_equally_sized() {
        let bytes: Vec<u8> = (0..12).collect();
        let transposed = crate::util::transpose(&bytes, 4);
        assert_eq!([0, 4, 8].to_vec(), transposed[0]);
        assert_eq!([1, 5, 9].to_vec(), transposed[1]);
        assert_eq!([2, 6, 10].to_vec(), transposed[2]);
        assert_eq!([3, 7, 11].to_vec(), transposed[3]);
    }

    #[test]
    fn transpose_unequally_sized() {
        let bytes: Vec<u8> = (0..10).collect();
        let transposed = crate::util::transpose(&bytes, 4);
        assert_eq!([0, 4, 8].to_vec(), transposed[0]);
        assert_eq!([1, 5, 9].to_vec(), transposed[1]);
        assert_eq!([2, 6].to_vec(), transposed[2]);
        assert_eq!([3, 7].to_vec(), transposed[3]);
    }

    #[test]
    fn xor_vec_zero() {
        let bytes = [0, 1, 2, 3, 4];
        assert_eq!(crate::util::xor_vec(&bytes, 0), bytes);
    }

    #[test]
    fn xor_vec_ff() {
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(crate::util::xor_vec(&bytes, 0xFF), [0, 0, 0, 0, 0]);
    }

    #[test]
    fn pad_empty() {
        let mut bytes = Vec::new();
        crate::util::pkcs7_pad(&mut bytes, 16);
        let empty: Vec<u8> = Vec::new();
        assert_eq!(empty, bytes);
    }

    #[test]
    fn pad() {
        let mut bytes = vec![1, 2, 3, 4];
        crate::util::pkcs7_pad(&mut bytes, 8);
        assert_eq!([1, 2, 3, 4, 4, 4, 4, 4].to_vec(), bytes);
    }

    #[test]
    fn pad_one_byte() {
        let mut bytes = vec![1, 2, 3, 4, 5, 6, 7];
        crate::util::pkcs7_pad(&mut bytes, 8);
        assert_eq!([1, 2, 3, 4, 5, 6, 7, 1].to_vec(), bytes);
    }

    #[test]
    fn unpad_empty() {
        let mut bytes = Vec::new();
        crate::util::pkcs7_unpad(&mut bytes);
        let empty: Vec<u8> = Vec::new();
        assert_eq!(empty, bytes);
    }

    #[test]
    fn unpad_four_bytes() {
        let mut bytes = vec![0x1, 0x2, 0x3, 0x4, 0x4, 0x4, 0x4, 0x4];
        crate::util::pkcs7_unpad(&mut bytes);
        assert_eq!([0x1, 0x2, 0x3, 0x4].to_vec(), bytes);
    }
}
