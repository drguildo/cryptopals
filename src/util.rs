// Find the Hamming distance between the specified strings.
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
}
