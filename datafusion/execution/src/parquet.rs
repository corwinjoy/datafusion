use arrow::datatypes::SchemaRef;
use dashmap::DashMap;
use datafusion_common::config::{EncryptionFactoryOptions, ExtensionOptions};
use datafusion_common::error::Result;
use datafusion_common::DataFusionError;
use object_store::path::Path;
use parquet::encryption::decrypt::FileDecryptionProperties;
use parquet::encryption::encrypt::FileEncryptionProperties;
use std::sync::Arc;

/// Trait for types that generate file encryption and decryption properties to
/// write and read encrypted Parquet files.
/// This allows flexibility in how encryption keys are managed, for example, to
/// integrate with a user's key management service (KMS).
pub trait EncryptionFactory: Send + Sync + std::fmt::Debug + 'static {
    /// The type to hold configuration options for this factory
    type Options: ExtensionOptions + Default;

    /// Generate file encryption properties to use when writing a Parquet file.
    fn get_file_encryption_properties(
        &self,
        config: &Self::Options,
        schema: &SchemaRef,
        file_path: &Path,
    ) -> Result<Option<FileEncryptionProperties>>;

    /// Generate file decryption properties to use when reading a Parquet file.
    fn get_file_decryption_properties(
        &self,
        config: &Self::Options,
        file_path: &Path,
    ) -> Result<Option<FileDecryptionProperties>>;
}

/// Dyn-compatible version of the [`EncryptionFactory`] trait
pub trait DynEncryptionFactory: Send + Sync + std::fmt::Debug + 'static {
    /// Generate file encryption properties to use when writing a Parquet file.
    fn get_file_encryption_properties(
        &self,
        config: &EncryptionFactoryOptions,
        schema: &SchemaRef,
        file_path: &Path,
    ) -> Result<Option<FileEncryptionProperties>>;

    /// Generate file decryption properties to use when reading a Parquet file.
    fn get_file_decryption_properties(
        &self,
        config: &EncryptionFactoryOptions,
        file_path: &Path,
    ) -> Result<Option<FileDecryptionProperties>>;
}

impl<T: EncryptionFactory> DynEncryptionFactory for T {
    fn get_file_encryption_properties(
        &self,
        config: &EncryptionFactoryOptions,
        schema: &SchemaRef,
        file_path: &Path,
    ) -> Result<Option<FileEncryptionProperties>> {
        let mut options = T::Options::default();
        for (key, value) in &config.options {
            options.set(key, value)?;
        }
        self.get_file_encryption_properties(&options, schema, file_path)
    }

    fn get_file_decryption_properties(
        &self,
        config: &EncryptionFactoryOptions,
        file_path: &Path,
    ) -> Result<Option<FileDecryptionProperties>> {
        let mut options = T::Options::default();
        for (key, value) in &config.options {
            options.set(key, value)?;
        }
        self.get_file_decryption_properties(&options, file_path)
    }
}

#[derive(Clone, Debug, Default)]
pub struct EncryptionFactoryRegistry {
    factories: DashMap<String, Arc<dyn DynEncryptionFactory>>,
}

impl EncryptionFactoryRegistry {
    pub fn register_factory(
        &self,
        id: &str,
        factory: Arc<dyn DynEncryptionFactory>,
    ) -> Option<Arc<dyn DynEncryptionFactory>> {
        self.factories.insert(id.to_owned(), factory)
    }

    pub fn get_factory(&self, id: &str) -> Result<Arc<dyn DynEncryptionFactory>> {
        self.factories
            .get(id)
            .map(|f| Arc::clone(f.value()))
            .ok_or_else(|| {
                DataFusionError::Internal(format!(
                    "No Parquet encryption factory found for id '{id}'"
                ))
            })
    }
}
