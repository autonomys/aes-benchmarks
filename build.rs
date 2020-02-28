extern crate cc;

fn main() {
    let mut cfg = cc::Build::new();
    cfg.file("src/vaes.c");
    cfg.compile("vaes_c.a");
}
