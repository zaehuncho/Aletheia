use aletheia_core::pe;
use aletheia_core::detect;
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let raw = std::fs::read(&path).unwrap();
    let info = pe::parse_bytes(&raw);
    let v = detect::analyze(&info, Some(&raw));
    println!("{}", v.summary());
    for s in v.signals { println!("  - {}", s); }
}
