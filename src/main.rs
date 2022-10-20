use cryptopals::util::encryption_oracle;

fn main() {
    let encrypted = encryption_oracle("This is some data.".as_bytes());
    println!("{:#x?}", encrypted);
}
