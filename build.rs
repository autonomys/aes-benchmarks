extern crate cc;

fn main() {
    cc::Build::new()
      .file("src/vaes.c")
      .compile("vaes_c.a");
}
