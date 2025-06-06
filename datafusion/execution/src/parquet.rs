use arrow::datatypes::SchemaRef;
use dashmap::DashMap;
use datafusion_common::config::TableParquetOptions;
use datafusion_common::DataFusionError;
#[cfg(feature = "parquet")]
use parquet::encryption::decrypt::FileDecryptionProperties;
#[cfg(feature = "parquet")]
use parquet::encryption::encrypt::FileEncryptionProperties;
use std::sync::Arc;

/// Trait for types that generate file encryption and decryption properties to
/// write and read encrypted Parquet files.
/// This allows flexibility in how encryption keys are managed, for example, to
/// integrate with a user's key management service (KMS).
#[cfg(feature = "parquet")]
pub trait EncryptionFactory: Send + Sync + std::fmt::Debug + 'static {
    /// Generate file encryption properties to use when writing a Parquet file.
    fn get_file_encryption_properties(
        &self,
        options: &TableParquetOptions,
        schema: SchemaRef,
        file_path: &str,
    ) -> datafusion_common::Result<FileEncryptionProperties>;

    /// Generate file decryption properties to use when reading a Parquet file.
    fn get_file_decryption_properties(
        &self,
        options: &TableParquetOptions,
        file_path: &str,
    ) -> datafusion_common::Result<FileDecryptionProperties>;
}

#[derive(Clone, Debug, Default)]
pub struct EncryptionFactoryRegistry {
    #[cfg(feature = "parquet")]
    factories: DashMap<String, Arc<dyn EncryptionFactory>>,
}

#[cfg(feature = "parquet")]
impl EncryptionFactoryRegistry {
    pub fn register_factory(
        &self,
        id: &str,
        factory: Arc<dyn EncryptionFactory>,
    ) -> Option<Arc<dyn EncryptionFactory>> {
        self.factories.insert(id.to_owned(), factory)
    }

    pub fn get_factory(
        &self,
        id: &str,
    ) -> datafusion_common::Result<Arc<dyn EncryptionFactory>> {
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
