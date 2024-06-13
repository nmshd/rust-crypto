use crate::common::crypto::{algorithms, KeyUsage};
use crate::common::factory::SecModules;
use crate::common::factory::SecurityModule;
use crate::tpm::android::*;
use crate::tpm::core::instance::AndroidTpmType;
use crate::tpm::core::instance::TpmType;
use robusta_jni::convert::IntoJavaValue;

#[test]
fn initializ_module_test1() {
    assert_eq!(true, true);
}

#[test]
fn initializ_module_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
        None,
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider.initialize_module().unwrap();
}
/*
#[test]
fn key_creation_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("2320").unwrap();
}

#[test]
fn key_load_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("2322").unwrap();
    provider.load_key("2322").unwrap();
}

/*
----------------TESTING different KeyBits------------------------
*/

#[test]
fn key_creation_bit_128_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits128);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("23128").unwrap();
}

#[test]
fn key_creation_bit_192_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits192);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("23192").unwrap();
}

#[test]
fn key_creation_bit_256_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits256);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("23256").unwrap();
}

#[test]
fn key_creation_bit_512_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits512);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("23512").unwrap();
}

#[test]
fn key_creation_bit_1024_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("231024").unwrap();
}

#[test]
fn key_creation_bit_2048_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits2048);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("232048").unwrap();
}

#[test]
fn key_creation_bit_3072_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits3072);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("233072").unwrap();
}

#[test]
fn key_creation_bit_4096_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits4096);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("234096").unwrap();
}

#[test]
fn key_creation_bit_8192_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits8192);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("238192").unwrap();
}

/*

---------------------TESTING Hashes-------------------

*/

#[test]
fn key_creation_hash_md2_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Md2;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("231025").unwrap();
}

#[test]
fn key_creation_hash_md4_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Md4;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("231026").unwrap();
}

#[test]
fn key_creation_hash_md5_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Md5;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("231027").unwrap();
}

/*

------------Testing KeyUsages--------------

*/

#[test]
fn key_creation_hash_ripemd160_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Ripemd160;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("231028").unwrap();
}

#[test]
fn key_creation_keyusage_clientauth_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::ClientAuth];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("231029").unwrap();
}

#[test]
fn key_creation_keyusage_decrypt_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::Decrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("231030").unwrap();
}

#[test]
fn key_creation_keyusage_createx509_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::CreateX509];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
    provider.create_key("231031").unwrap();
}

/*

---------------Sign Data------------------

*/

#[test]
fn sign_data_1_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();

    let data = b"testing";

    provider.sign_data(data);
}

#[test]
fn sign_data_2_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();

    let data = b"h";

    provider.sign_data(data);
}

//How to expect a fail??
#[test]
fn sign_data_3_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();

    let data = b"";

    provider.sign_data(data);
}

//How to expect a fail??
#[test]
fn sign_data_4_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();

    let data = b"overflowing";

    provider.sign_data(data);
}

//Test different Key Ids => 0?

#[test]
fn verify_signature_1_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();

    let data = b"test";

    let signature = provider.sign_data(data).unwrap();

    //Convert Vec<u8> to list u8

    let mut signature_list: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

    for (place, element) in signature_list.iter_mut().zip(signature.into_iter()) {
        unsafe { std::ptr::write(place, element) };
    }
    let verified = provider
        .verify_signature(data, &signature_list)
        .unwrap_or_default();

    assert_eq!(true, verified);
}

#[test]
fn verify_signature_2_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();

    let data = b"testingX";

    let signature = provider.sign_data(data).unwrap();

    //Convert Vec<u8> to list u8

    let mut signature_list: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

    for (place, element) in signature_list.iter_mut().zip(signature.into_iter()) {
        unsafe { std::ptr::write(place, element) };
    }
    let verified = provider
        .verify_signature(data, &signature_list)
        .unwrap_or_default();

    assert_eq!(true, verified);
}

#[test]
fn verify_signature_3_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();

    let data = b"H";

    let signature = provider.sign_data(data).unwrap();

    //Convert Vec<u8> to list u8

    let mut signature_list: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

    for (place, element) in signature_list.iter_mut().zip(signature.into_iter()) {
        unsafe { std::ptr::write(place, element) };
    }
    let verified = provider
        .verify_signature(data, &signature_list)
        .unwrap_or_default();

    assert_eq!(true, verified);
}

#[test]
fn verify_signature_4_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();

    let data = b"";

    let signature = provider.sign_data(data).unwrap();

    let mut signature_list: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

    for (place, element) in signature_list.iter_mut().zip(signature.into_iter()) {
        unsafe { std::ptr::write(place, element) };
    }
    let verified = provider
        .verify_signature(data, &signature_list)
        .unwrap_or_default();

    assert_eq!(false, verified);
}

#[test]
fn encrypt_data_1_test() {
    let security_module = SecModules::get_instance(
        "2323".to_string(),
        SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Keystore)),
    );

    let x = security_module.unwrap();
    let mut provider = x.lock().unwrap();
    let key_algorithm =
        algorithms::encryption::AsymmetricEncryption::Rsa(algorithms::KeyBits::Bits1024);
    let hash = algorithms::hashes::Hash::Sha1;
    let key_usages = vec![KeyUsage::SignEncrypt];
    provider
        .initialize_module(key_algorithm, None, Some(hash), key_usages)
        .unwrap();
}
*/
