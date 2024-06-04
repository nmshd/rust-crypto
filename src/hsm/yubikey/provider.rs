use super::YubiKeyProvider;
use crate::common::{
    crypto::{
        algorithms::{
            encryption::{AsymmetricEncryption, EccCurves, EccSchemeAlgorithm},
            KeyBits,
        },
        KeyUsage,
    },
    error::SecurityModuleError,
    traits::module_provider::Provider,
};
use crate::hsm::{core::error::HsmError, HsmProviderConfig, ProviderConfig};
use ::yubikey::{
    piv::{self, AlgorithmId, RetiredSlotId, SlotId},
    Error, YubiKey,
};
use base64::{engine::general_purpose, Engine};
use std::sync::{Arc, Mutex};
use tracing::instrument;
use x509_cert::der::Encode;
use yubikey::MgmKey;

const SLOTS: [RetiredSlotId; 20] = [
    RetiredSlotId::R1,
    RetiredSlotId::R2,
    RetiredSlotId::R3,
    RetiredSlotId::R4,
    RetiredSlotId::R5,
    RetiredSlotId::R6,
    RetiredSlotId::R7,
    RetiredSlotId::R8,
    RetiredSlotId::R9,
    RetiredSlotId::R10,
    RetiredSlotId::R11,
    RetiredSlotId::R12,
    RetiredSlotId::R13,
    RetiredSlotId::R14,
    RetiredSlotId::R15,
    RetiredSlotId::R16,
    RetiredSlotId::R17,
    RetiredSlotId::R18,
    RetiredSlotId::R19,
    RetiredSlotId::R20,
];

const SLOTSU32: [u32; 20] = [
    0x005f_c10d,
    0x005f_c10e,
    0x005f_c10f,
    0x005f_c110,
    0x005f_c111,
    0x005f_c112,
    0x005f_c113,
    0x005f_c114,
    0x005f_c115,
    0x005f_c116,
    0x005f_c117,
    0x005f_c118,
    0x005f_c119,
    0x005f_c11a,
    0x005f_c11b,
    0x005f_c11c,
    0x005f_c11d,
    0x005f_c11e,
    0x005f_c11f,
    0x005f_c120,
];

/// Implements the `Provider` trait, providing cryptographic operations utilizing a YubiKey.
///
/// This implementation interacts with a YubiKey device for key management and cryptographic
/// operations.
impl Provider for YubiKeyProvider {
    /// Creates a new cryptographic key identified by the provider given key_id.
    ///
    /// This method creates a persisted cryptographic key using the specified algorithm
    /// and identifier, making it retrievable for future operations. The key is created
    /// with the specified key usages and stored in the YubiKey.
    ///
    /// # Arguments
    ///
    ///
    /// # Returns
    ///
    /// The generated Public Key will be stored in the Yubikey as Object with futher information
    /// A `Result` that, on success, contains `Ok()`.
    /// On failure, it returns a `yubikey::Error`.
    #[instrument]
    fn create_key(
        &mut self,
        key_id: &str,
        config: Box<dyn ProviderConfig>,
    ) -> Result<(), SecurityModuleError> {
        if let Some(hsm_config) = config.as_any().downcast_ref::<HsmProviderConfig>() {
            self.key_algo = Some(hsm_config.key_algorithm);
            self.key_usages = Some(hsm_config.key_usage.clone());
            let key_algo = self.key_algo.clone().unwrap();

            let mut usage: &str = "";
            let slot: u32;
            let key_usages = self.key_usages.clone().unwrap();
            let slot_id;

            if !(self.load_key(key_id, config).is_ok()) {
                let mut yubikey = self.yubikey.as_ref().unwrap().lock().unwrap();
                let _ = yubikey.verify_pin("123456".as_ref());
                let _ = yubikey.authenticate(MgmKey::default());
                match get_free_slot(&mut yubikey) {
                    Ok(free) => {
                        slot_id = free;
                    }
                    Err(err) => {
                        return Err(SecurityModuleError::InitializationError(err.to_string()));
                    }
                }
            } else {
                slot_id = self.slot_id.unwrap();
            }

            fn generate_key(
                mut yubikey: &mut YubiKey,
                algorithm: AlgorithmId,
                slot_id: RetiredSlotId,
            ) -> Result<(RetiredSlotId, String), SecurityModuleError> {
                let pkey: String;

                let _ = yubikey.verify_pin("123456".as_ref());
                let _ = yubikey.authenticate(MgmKey::default());

                let gen_key = piv::generate(
                    &mut yubikey,
                    SlotId::Retired(slot_id),
                    algorithm,
                    yubikey::PinPolicy::Default,
                    yubikey::TouchPolicy::Default,
                );
                match gen_key {
                    Ok(_) => {
                        let gen_key = gen_key.as_ref().unwrap().to_der().unwrap();
                        let gen_key = general_purpose::STANDARD.encode(&gen_key);
                        let gen_key = format!(
                            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                            gen_key.trim()
                        );
                        pkey = gen_key;
                    }
                    Err(err) => {
                        return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                            err.to_string(),
                        )))
                    }
                }
                Ok((slot_id, pkey))
            }

            match *key_usages.get(0).unwrap() {
                KeyUsage::SignEncrypt => match key_algo {
                    AsymmetricEncryption::Rsa(KeyBits::Bits1024) => {
                        let mut yubikey = self.yubikey.as_ref().unwrap().lock().unwrap();
                        let (slot_id, pkey) =
                            generate_key(&mut yubikey, AlgorithmId::Rsa1024, slot_id).unwrap();
                        self.slot_id = Some(slot_id);
                        self.pkey = pkey;

                        usage = "SignEncrypt";
                    }
                    AsymmetricEncryption::Rsa(KeyBits::Bits2048) => {
                        let mut yubikey = self.yubikey.as_ref().unwrap().lock().unwrap();
                        let (slot_id, pkey) =
                            generate_key(&mut yubikey, AlgorithmId::Rsa2048, slot_id).unwrap();
                        self.slot_id = Some(slot_id);
                        self.pkey = pkey;

                        usage = "SignEncrypt";
                    }
                    AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P256)) => {
                        let mut yubikey = self.yubikey.as_ref().unwrap().lock().unwrap();
                        let (slot_id, pkey) =
                            generate_key(&mut yubikey, AlgorithmId::EccP256, slot_id).unwrap();
                        self.slot_id = Some(slot_id);
                        self.pkey = pkey;

                        usage = "SignEncrypt";
                    }
                    AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P384)) => {
                        let mut yubikey = self.yubikey.as_ref().unwrap().lock().unwrap();
                        let (slot_id, pkey) =
                            generate_key(&mut yubikey, AlgorithmId::EccP384, slot_id).unwrap();
                        self.slot_id = Some(slot_id);
                        self.pkey = pkey;

                        usage = "SignEncrypt";
                    }
                    _ => {
                        return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                            "Key Algorithm not supported".to_string(),
                        )));
                    }
                },

                KeyUsage::Decrypt => {
                    match key_algo {
                        AsymmetricEncryption::Rsa(KeyBits::Bits1024) => {
                            let mut yubikey = self.yubikey.as_ref().unwrap().lock().unwrap();
                            let (slot_id, pkey) =
                                generate_key(&mut yubikey, AlgorithmId::Rsa1024, slot_id).unwrap();
                            self.slot_id = Some(slot_id);
                            self.pkey = pkey;

                            usage = "Decrypt";
                        }
                        AsymmetricEncryption::Rsa(KeyBits::Bits2048) => {
                            let mut yubikey = self.yubikey.as_ref().unwrap().lock().unwrap();
                            let (slot_id, pkey) =
                                generate_key(&mut yubikey, AlgorithmId::Rsa2048, slot_id).unwrap();
                            self.slot_id = Some(slot_id);
                            self.pkey = pkey;

                            usage = "Decrypt";
                        }
                        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P256)) => {
                            // TODO, not tested, might work
                        }
                        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P384)) => {
                            // TODO, not tested, might work
                        }
                        _ => {
                            return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                                "Key Algorithm not supported".to_string(),
                            )));
                        }
                    }
                }

                _ => {
                    return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                        "Key Usage not supported".to_string(),
                    )));
                }
            }

            let mut yubikey = self.yubikey.as_ref().unwrap().lock().unwrap();

            let pkey = self.pkey.clone();
            slot = get_reference_u32slot(self.slot_id.unwrap());

            let _ = yubikey.verify_pin("123456".as_ref());
            let _ = yubikey.authenticate(MgmKey::default());

            match save_key_object(&mut yubikey, usage, key_id, slot, &pkey) {
                Ok(_) => Ok(()),
                Err(err) => {
                    return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                        err.to_string(),
                    )))
                }
            }
        } else {
            Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                "Failed to get the Configurations".to_string(),
            )))
        }
    }

    /// Loads an existing cryptographic key identified by `key_id`.
    ///
    /// This method attempts to load a persisted cryptographic key by its identifier from the YubiKey.
    /// If successful, it sets the key usages and returns a handle to the key for further
    /// cryptographic operations.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be loaded.
    /// * `config` - A boxed `ProviderConfig` containing configuration details for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was loaded successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    fn load_key(
        &mut self,
        key_id: &str,
        config: Box<dyn ProviderConfig>,
    ) -> Result<(), SecurityModuleError> {
        let mut yubikey = self.yubikey.as_ref().unwrap().lock().unwrap();
        let mut found = false;
        for i in 10..19 {
            let _ = yubikey.verify_pin("123456".as_ref());
            let _ = yubikey.authenticate(MgmKey::default());
            let data = yubikey.fetch_object(SLOTSU32[i]);
            let mut output: Vec<u8> = Vec::new();
            match data {
                Ok(data) => {
                    output = data.to_vec();
                }
                Err(err) => {
                    println!("Error: {:?}", err);
                }
            }

            let data = output;
            match parse_slot_data(&data) {
                Ok((key_name, _, usage, public_key)) => {
                    if key_name == key_id.to_string() {
                        let mut vector = Vec::new();
                        self.slot_id = Some(SLOTS[i - 10]);
                        self.key_usages = match usage.as_str() {
                            "SignEncrypt" => {
                                vector.push(KeyUsage::SignEncrypt);
                                Some(vector)
                            }
                            "Decrypt" => {
                                vector.push(KeyUsage::Decrypt);
                                Some(vector)
                            }
                            _ => continue,
                        };
                        self.pkey = public_key;
                        found = true;
                        break;
                    }
                }
                Err(e) => {
                    println!("Error arsching slot data: {:?}", e);
                    continue;
                }
            }
        }

        if !found {
            return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                "Key not found".to_string(),
            )));
        } else {
            Ok(())
        }
    }

    /// Initializes the YubiKey module and returns a handle for cryptographic operations.
    ///
    /// This method initializes the YubiKey device and sets up the necessary environment
    /// for cryptographic operations.
    ///
    /// # Arguments
    ///
    /// * `key_algorithm` - The asymmetric encryption algorithm to be used for the key.
    /// * `hash` - An optional hash algorithm to be used with the key.
    /// * `key_usages` - A vector of `KeyUsage` values specifying the intended usages for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the module was initialized successfully.
    /// On failure, it returns a Yubikey based `Error`.
    #[instrument]
    fn initialize_module(&mut self) -> Result<(), SecurityModuleError> {
        let mut yubikey = YubiKey::open().map_err(|_| Error::NotFound).unwrap();

        let verify = yubikey
            .verify_pin("123456".as_ref())
            .map_err(|_| Error::WrongPin {
                tries: yubikey.get_pin_retries().unwrap(),
            });

        self.yubikey = Some(Arc::new(Mutex::new(yubikey)));

        if verify.is_ok() {
            return Ok(());
        } else {
            return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                "Failed to verify PIN, retries: {}".to_string(),
            )));
        }
    }
}

/// Saves the key object to the YubiKey device.
///
/// This method saves a object to the YubiKey device. The object is stored in a slot and represents
/// information about the key, such as the key name, slot, key usage, and public key. This information
/// belongs to a private key which is stored in a other Slot.
///
/// # Arguments
/// 'usage' - The key usage of the key object to be stored.
///
/// # Returns
///
/// The saved Object will be stored in the Yubikey on a free Retired slot as Object with futher information
/// A `Result` that, on success, contains `Ok()`.
/// On failure, it returns a `yubikey::Error`.
fn save_key_object(
    yubikey: &mut YubiKey,
    usage: &str,
    key_id: &str,
    slot_id: u32,
    pkey: &str,
) -> Result<(), yubikey::Error> {
    let key_name = key_id;
    let slot = slot_id.to_string();
    let public_key = pkey;

    let total_length = key_name.len() + 1 + slot.len() + 1 + usage.len() + 1 + public_key.len();
    let mut data = vec![0u8; total_length];
    let data_slice: &mut [u8] = &mut data;

    let mut offset = 0;
    data_slice[offset..offset + key_name.len()].copy_from_slice(key_name.as_bytes());
    offset += key_name.len();
    data_slice[offset] = 0;
    offset += 1;

    data_slice[offset..offset + slot.len()].copy_from_slice(slot.as_bytes());
    offset += slot.len();
    data_slice[offset] = 0;
    offset += 1;

    data_slice[offset..offset + usage.len()].copy_from_slice(usage.as_bytes());
    offset += usage.len();
    data_slice[offset] = 0;
    offset += 1;

    data_slice[offset..offset + public_key.len()].copy_from_slice(public_key.as_bytes());

    let saved = yubikey.save_object(slot_id, data_slice);
    match saved {
        Ok(()) => Ok(()),
        Err(err) => Err(err),
    }
}

/// parses the u8 Data to different Key-Information Strings
///
/// This method creates a persisted cryptographic key using the specified algorithm
/// and identifier, making it retrievable for future operations. The key is created
/// with the specified key usages and stored in the YubiKey.
///
/// # Arguments
///
///
/// # Returns
///
/// A `Result` that, on success, contains `Ok(key_name, slot, key_usage, public_key)` where the individual information is given.
/// On failure, it returns a `Utf8Error`.
fn parse_slot_data(data: &[u8]) -> Result<(String, String, String, String), SecurityModuleError> {
    let parts: Vec<&[u8]> = data.split(|&x| x == 0).collect();
    if !(parts.len() < 4
        || parts[0].is_empty()
        || parts[1].is_empty()
        || parts[2].is_empty()
        || parts[3].is_empty())
    {
        let key_name = std::str::from_utf8(parts[0]).unwrap();
        let slot = std::str::from_utf8(parts[1]).unwrap();
        let usage = std::str::from_utf8(parts[2]).unwrap();
        let public_key = std::str::from_utf8(parts[3]).unwrap();

        Ok((
            key_name.to_string(),
            slot.to_string(),
            usage.to_string(),
            public_key.to_string(),
        ))
    } else {
        return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
            "Failed to verify PIN, retries: {}".to_string(),
        )));
    }
}

/// Gets a free slot for storing a key object.
///
/// This method goes through the available slots on the YubiKey and returns the first free slot
///
/// # Arguments
///
///
/// # Returns
///
/// A `Result` that, on failure, returns the first free slot.
/// On Success, it returns that no more free slots are available.
fn get_free_slot(yubikey: &mut YubiKey) -> Result<RetiredSlotId, SecurityModuleError> {
    let mut end;
    let mut slot_id: RetiredSlotId = SLOTS[0];
    for i in 10..19 {
        let data = yubikey.fetch_object(SLOTSU32[i]);
        let mut output: Vec<u8> = Vec::new();
        match data {
            Ok(data) => {
                output = data.to_vec();
            }
            Err(err) => {
                println!("Error: {:?}", err);
            }
        }
        let data = output;
        match parse_slot_data(&data) {
            Ok(_) => {
                continue;
            }
            Err(_) => {
                slot_id = SLOTS[i - 10];
                end = true;
            }
        }
        if end {
            break;
        }
    }
    Ok(slot_id)
}

/// Converts a `RetiredSlotId` to its corresponding u32 value.
///
/// This method converts a `RetiredSlotId` to its corresponding u32 value,
/// which is required for slot operations on the YubiKey device.
///
/// # Arguments
///
/// * `slot` - The `RetiredSlotId` to be converted.
///
/// # Returns
///
/// The corresponding u32 value of the `RetiredSlotId`.
fn get_reference_u32slot(slot: RetiredSlotId) -> u32 {
    let mut output: u32 = SLOTSU32[0];
    for i in 0..19 {
        if SLOTS[i] == slot {
            output = SLOTSU32[i + 10];
            break;
        } else {
            continue;
        }
    }
    output
}

// Halbfertiger Code, kann benutzt werden wenn PIN-Abfrage in App implementiert wird
/*
#[instrument]
fn initialize_module(
    &mut self,
    key_algorithm: AsymmetricEncryption,
    sym_algorithm: Option<BlockCiphers>,
    hash: Option<Hash>,
    key_usage: Vec<KeyUsage>,
    input: &str,
) -> Result<device, SecurityModuleError> {
    // Opens a connection to the yubikey device
    loop {
        let yubikey = YubiKey::open();
        if yubikey.is_ok() {
            let verify = device.verify_pin(input);
            if verify.is_ok() {
                //successful login
                return device;
            } else {
                let count = device.get_pin_retries().unwrap();
                // TODO: Implement PUK handling
                if count == 0 {
                    return yubiKey::Error::PinLocked;
                    /*  let puk;
                    let pin_neu;
                    let change_puk = device.unblock_pin(puk.as_ref(), pin_neu.as_ref());
                    if change_puk.is_ok() {
                        return device;
                        */
                }
                return yubikey::Errror::WrongPin;
            }
        }
    }
}
*/
