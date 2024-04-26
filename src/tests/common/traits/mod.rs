use crate::{
    common::{factory::SecurityModule, traits::module_provider::Provider},
    tpm::{core::instance::TpmType, linux::TpmProvider, win::TpmProvider as WindowsTpmProvider},
};

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
            TpmType::Windows => Box::new(WindowsTpmProvider::new("test_key".to_string())),
            TpmType::None => unimplemented!(),
        },
        // _ => unimplemented!(),
    }
}
