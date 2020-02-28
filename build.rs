extern crate cc;

fn main() {
    cc::Build::new()
      .file("src/vaes.c")
      .opt_level(3)
      .flag("-flto")
      .compile("vaes_c.a");
}
