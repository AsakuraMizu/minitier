use std::fs;

use rcgen::{generate_simple_self_signed, CertifiedKey};

fn main() {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["chuni.stellopath.net".into()]).unwrap();
    fs::write("cert.der", cert.der()).unwrap();
    fs::write("key.der", key_pair.serialize_der()).unwrap();
}
