mod lib;
use lib::*;

fn main() {
    
    // generate random key and plaintext
    let key = random_bytes_16();
    let plaintext = random_bytes_16();

    println!("Key: {:?}", key);
    println!("Plaintext: {:?}", plaintext);

    // encode and decode
    unsafe {
      let ciphertext = encode(key, plaintext, 2);
      println!("Ciphertext: {:?}", ciphertext);
      let decodedtext = decode(key, ciphertext, 2);
      println!("Decoded text: {:?}", decodedtext);
      
      // let ciphertext = encode(key, plaintext, 66000);
      // println!("Ciphertext: {:?}", ciphertext);
      // let decodedtext = decode(key, ciphertext, 66000);
      // println!("Decoded text: {:?}", decodedtext);

      // ensure plaintext is the same
      assert_eq!(plaintext, decodedtext);
    } 
    
}

