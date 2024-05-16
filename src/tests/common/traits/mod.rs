use crate::{
    common::{factory::SecurityModule, traits::module_provider::Provider},
    // tpm::{core::instance::TpmType, linux::TpmProvider, win::TpmProvider as WindowsTpmProvider},
};
use crate::nks::hcvault::NksProvider;
#[cfg(feature = "tpm")]
use crate::tpm::core::instance::TpmType;
#[cfg(feature = "tpm")]
use crate::tpm::linux::TpmProvider;

pub mod key_handle;
pub mod module_provider;

fn setup_security_module(module: SecurityModule) -> Box<dyn Provider> {
    match module {
        #[cfg(feature = "hsm")]
        SecurityModule::Hsm(_hsm_type) => {
            unimplemented!()
            // Box::new(HsmProvider::new("test_key".to_string(), hsm_type))
        }
        #[cfg(feature = "tpm")]
        SecurityModule::Tpm(tpm_type) => match tpm_type {
            TpmType::Linux => Box::new(TpmProvider::new("test_key".to_string())),
            TpmType::None => unimplemented!(),
            _ => unimplemented!()
        },
        #[cfg(feature = "nks")]
        SecurityModule::Nks => Box::new(NksProvider::new("test_key".to_string())),
        _ => unimplemented!(), // Add this line to handle all other cases
    }
}