#[cfg(test)]
mod test {
    #[test]
    fn challenge9() {
        let padded = crate::util::pkcs7_pad("YELLOW SUBMARINE".as_bytes(), 20);
        assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(), padded);
    }
}
