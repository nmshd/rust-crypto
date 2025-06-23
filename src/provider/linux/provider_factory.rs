use std::collections::HashSet;

use anyhow::anyhow;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::{SessionType, StartupType};
use tss_esapi::structures::{
    Data, EccPoint, PublicBuilder, PublicEccParametersBuilder, SymmetricDefinition,
    SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::NetworkTPMConfig;
use tss_esapi::Context;
use tss_esapi::{interface_types::resource_handles::Hierarchy, tcti_ldr::TctiNameConf};

use crate::{
    common::traits::module_provider::{ProviderFactory, ProviderImplEnum},
    prelude::{CalError, ProviderConfig, ProviderImplConfig, SecurityLevel},
    provider::linux::provider::LinuxProvider,
    storage::StorageManager,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct LinuxProviderFactory;

impl ProviderFactory for LinuxProviderFactory {
    fn get_name(&self) -> Option<String> {
        // TODO: check if TPM is accessible
        Some(super::NAME.to_owned())
    }

    fn get_capabilities(&self, _impl_config: ProviderImplConfig) -> Option<ProviderConfig> {
        Some(ProviderConfig {
            min_security_level: SecurityLevel::Hardware,
            max_security_level: SecurityLevel::Hardware,
            supported_asym_spec: HashSet::new(),
            supported_ciphers: HashSet::new(),
            supported_hashes: HashSet::new(),
        })
    }

    fn create_provider(
        &self,
        impl_config: ProviderImplConfig,
    ) -> Result<ProviderImplEnum, CalError> {
        let storage_manager = StorageManager::new(
            self.get_name().expect("getting name should never fail"),
            &impl_config.additional_config,
        )?;

        let tcti = TctiNameConf::Mssim(NetworkTPMConfig::default());

        let mut context = Context::new(tcti).map_err(|e| {
            CalError::failed_init("failed to initialize tpm2 context", false, Some(anyhow!(e)))
        })?;

        // TODO: Do real tpms have to be started too?
        context
            .startup(StartupType::Clear)
            .map_err(|e| CalError::failed_init("failed to start tpm", false, Some(anyhow!(e))))?;

        let auth_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
            )
            .map_err(|e| {
                CalError::failed_init("Failed to create session", false, Some(anyhow!(e)))
            })?;

        context.set_sessions((auth_session, None, None));

        let object_attributes = ObjectAttributesBuilder::new()
            .with_decrypt(true)
            .with_fixed_tpm(true)
            .with_restricted(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .build()
            .expect("ObjectAttributesBuilder should never fail");

        let ecc_parameters = PublicEccParametersBuilder::new()
            .with_curve(tss_esapi::interface_types::ecc::EccCurve::NistP256)
            .with_ecc_scheme(tss_esapi::structures::EccScheme::Null)
            .with_is_decryption_key(true)
            .with_key_derivation_function_scheme(
                tss_esapi::structures::KeyDerivationFunctionScheme::Null,
            )
            .with_restricted(true)
            .with_symmetric(SymmetricDefinitionObject::Aes {
                key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes256,
                mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cbc,
            })
            .build()
            .expect("PublicEccParametersBuilder should never fail");

        let public_config = PublicBuilder::new()
            .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Ecc)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_parameters)
            .with_ecc_unique_identifier(EccPoint::default())
            .with_name_hashing_algorithm(
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
            )
            .build()
            .expect("PublicBuilder should never fail");

        let primary_key = context
            .create_primary(
                Hierarchy::Null,
                public_config,
                None,
                Some(
                    "unique_string"
                        .as_bytes()
                        .try_into()
                        .expect("unique init data should be Data"),
                ),
                None,
                None,
            )
            .map_err(|e| {
                CalError::failed_init("Failed to create primary key", false, Some(anyhow!(e)))
            })?
            .key_handle;

        Ok(ProviderImplEnum::from(LinuxProvider {
            context,
            primary_key,
            impl_config,
            used_factory: *self,
            storage_manager,
        }))
    }
}
