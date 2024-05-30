// use std::{path::PathB pub uf, process::Command};

// fn main() {
    // Ausführen des Signatur-Skripts
    // let status = Command::new("sh")
    //     .arg("codesigning.sh")
    //     .status()
    //     .expect("Failed to execute codesigning.sh");

    // if !status.success() {
    //     panic!("codesigning.sh failed");
    // }
    //This Teststring is Used in Encrypt, Sign and Verify
//     let test_string = "Hello World"; 

//     // Modul gets initialized. When initialization was successfull than the process proceed.
//     println!("\n"); 
//     if ffi::initializeModule() == true {
//         println!("Initialize Module: true"); 
//         println!("\n"); 

//         let priv_key: String = "3344".to_string(); 
//         println!("{}", ffi::rustcall_create_key(priv_key)); 
//         println!("\n"); 

//         println!("Loaded Key Hash: {}", ffi::rustcall_load_key("3344".to_string()));
//         println!("\n");

//         let encrypted_data = ffi::rustcall_encrypt_data(test_string.to_string(), "3344".to_string()); 
//         println!("Encrypted Data of {}:  {}", test_string.to_string(), encrypted_data);
//         println!("\n"); 

//         let decrypted_data = ffi::rustcall_decrypt_data(encrypted_data, "3344".to_string()); 
//         println!("Decrypted Data: {}", decrypted_data); 
//         println!("\n"); 

//         let signed_data = ffi::rustcall_sign_data(test_string.to_string(),"3344".to_string()); 
//         println!("Signed Data: {}", signed_data); 
//         println!("\n");

//         println!("Verify Signature: {}", ffi::rustcall_verify_data(test_string.to_string(), signed_data.to_string(), "3344".to_string())); 
//         println!("\n"); 
//     }else{
//         println!("Initialize Module: false")
//     }
// }

#[swift_bridge::bridge] // TODO
pub mod ffi{
    // Swift-Methods can be used in Rust 
    extern "Swift" {
        fn rustcall_create_key(privateKeyName: String) -> String;
        fn initializeModule() -> bool; 
        fn rustcall_load_key(keyID: String) -> String;
        fn rustcall_encrypt_data(data: String, publicKeyName: String) -> String; 
        fn rustcall_decrypt_data(data: String, privateKeyName: String) -> String; 
        fn rustcall_sign_data(data: String, privateKeyName: String) -> String;
        fn rustcall_verify_data(data: String, signature: String, publicKeyName: String) -> String; 
    }
}

pub mod key_handle{
    use crate::ffi;

    pub fn rust_crypto_call_create_key() -> String{
        ffi::rustcall_create_key("3344".to_string())


        
    }
      pub fn rust_crypto_call_load_key() -> String{
        ffi::rustcall_load_key("3344".to_string())


        
    }
}


