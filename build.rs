// disable warning for "CargoCallbacks" to use "CargoCallbacks::new" instead.
// The message is not valid for imports, only for implementations
#[allow(deprecated)]
use bindgen::CargoCallbacks;

fn main() {
    if std::env::var("CARGO_FEATURE_SODIUM_TESTS").is_ok() {
        let wrapper_header = "src/tests/software/sodium_cpp/wrapper.h";
        println!("cargo:rerun-if-changed={}", wrapper_header);
        println!("cargo:rustc-link-lib=sodium");

        let bindings = bindgen::Builder::default()
            .header(wrapper_header)
            .parse_callbacks(Box::new(CargoCallbacks::new()))
            // For Ed25519:
            .allowlist_function("sodium_init")
            .allowlist_function("crypto_sign_ed25519_keypair")
            .allowlist_function("crypto_sign_ed25519_detached")
            .allowlist_function("crypto_sign_ed25519_verify_detached")
            .allowlist_var("crypto_sign_ed25519_.*")
            // For AES-256-GCM:
            .allowlist_function("crypto_aead_aes256gcm_is_available")
            .allowlist_function("crypto_aead_aes256gcm_encrypt")
            .allowlist_function("crypto_aead_aes256gcm_decrypt")
            .allowlist_function("randombytes_buf")
            .allowlist_var("crypto_aead_aes256gcm_.*")
            // XChaCha20-Poly1305
            .allowlist_function("crypto_aead_xchacha20poly1305_ietf_encrypt")
            .allowlist_function("crypto_aead_xchacha20poly1305_ietf_decrypt")
            .allowlist_function("crypto_pwhash_argon2id")
            .allowlist_var("crypto_aead_xchacha20poly1305_ietf_.*")
            .allowlist_var("crypto_pwhash_argon2id_ALG_ARGON2ID13")
            .generate()
            .expect("Unable to generate libsodium bindings via bindgen");

        let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("sodium_bindings.rs"))
            .expect("Couldn't write libsodium bindings!");
    }
}
