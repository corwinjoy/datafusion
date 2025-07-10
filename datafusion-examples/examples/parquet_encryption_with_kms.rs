// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use arrow::array::{ArrayRef, Int32Array, RecordBatch, StringArray};
use arrow_schema::SchemaRef;
use datafusion::common::{extensions_options, DataFusionError};
use datafusion::config::TableParquetOptions;
use datafusion::dataframe::DataFrameWriteOptions;
use datafusion::datasource::file_format::parquet::ParquetFormat;
use datafusion::datasource::listing::ListingOptions;
use datafusion::error::Result;
use datafusion::execution::parquet_encryption::EncryptionFactory;
use datafusion::prelude::SessionContext;
use futures::StreamExt;
use object_store::path::Path;
use parquet::encryption::decrypt::FileDecryptionProperties;
use parquet::encryption::encrypt::FileEncryptionProperties;
use parquet_key_management::crypto_factory::{
    CryptoFactory, DecryptionConfiguration, EncryptionConfiguration,
};
use parquet_key_management::kms::KmsConnectionConfig;
use parquet_key_management::test_kms::TestKmsClientFactory;
use std::fmt::Formatter;
use std::sync::Arc;
use tempfile::TempDir;

/// This example demonstrates reading and writing Parquet files that
/// are encrypted using Parquet Modular Encryption, and uses the
/// parquet-key-management crate to integrate with a Key Management Server (KMS).

const ENCRYPTION_FACTORY_ID: &'static str = "example.memory_kms_encryption";

#[tokio::main]
async fn main() -> Result<()> {
    let ctx = SessionContext::new();

    // Register an `EncryptionFactory` implementation to be used for Parquet encryption
    // in the session context.
    // This example uses an in-memory test KMS from the `parquet_key_management` crate with
    // a custom `KmsEncryptionFactory` wrapper type to integrate with DataFusion.
    // `EncryptionFactory` instances are registered with a name to identify them so
    // they can be later referenced in configuration options, and it's possible to register
    // multiple different factories to handle different ways of encrypting Parquet.
    // In future it could be possible to have built-in implementations in DataFusion.
    let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
    let encryption_factory = KmsEncryptionFactory { crypto_factory };
    ctx.register_parquet_encryption_factory(
        ENCRYPTION_FACTORY_ID,
        Arc::new(encryption_factory),
    );

    // Register some simple test data
    let a: ArrayRef = Arc::new(StringArray::from(vec!["a", "b", "c", "d"]));
    let b: ArrayRef = Arc::new(Int32Array::from(vec![1, 10, 10, 100]));
    let batch = RecordBatch::try_from_iter(vec![("a", a), ("b", b)])?;
    ctx.register_batch("test_data", batch)?;

    {
        // Write and read with the programmatic API
        let tmpdir = TempDir::new()?;
        write_encrypted(&ctx, &tmpdir).await?;
        let file_path = std::fs::read_dir(&tmpdir)?.next().unwrap()?.path();
        read_encrypted(&ctx, &file_path).await?;
    }

    {
        // Write and read with the SQL API
        let tmpdir = TempDir::new()?;
        write_encrypted_with_sql(&ctx, &tmpdir).await?;
        let file_path = std::fs::read_dir(&tmpdir)?.next().unwrap()?.path();
        read_encrypted_with_sql(&ctx, &file_path).await?;
    }

    Ok(())
}

/// Write an encrypted Parquet file
async fn write_encrypted(ctx: &SessionContext, tmpdir: &TempDir) -> Result<()> {
    let df = ctx.table("test_data").await?;

    let mut parquet_options = TableParquetOptions::new();
    // We specify that we want to use Parquet encryption by setting the identifier of the
    // encryption factory to use and providing the factory specific configuration.
    // Our encryption factory requires specifying the master key identifier to
    // use for encryption.
    let mut encryption_config = KmsEncryptionConfig::default();
    encryption_config.footer_key_id = "kf".to_owned();
    parquet_options
        .crypto
        .set_factory(ENCRYPTION_FACTORY_ID, &encryption_config);

    df.write_parquet(
        tmpdir.path().to_str().unwrap(),
        DataFrameWriteOptions::new(),
        Some(parquet_options),
    )
    .await?;

    println!("Encrypted Parquet written to {:?}", tmpdir.path());
    Ok(())
}

/// Read from an encrypted Parquet file
async fn read_encrypted(ctx: &SessionContext, file_path: &std::path::Path) -> Result<()> {
    let mut parquet_options = TableParquetOptions::new();
    // Specify the encryption factory to use for decrypting Parquet.
    // In this example, we don't require any additional configuration options when reading
    // as key identifiers are stored in the key metadata.
    parquet_options
        .crypto
        .set_factory(ENCRYPTION_FACTORY_ID, &KmsEncryptionConfig::default());

    let file_format = ParquetFormat::default().with_options(parquet_options);
    let listing_options = ListingOptions::new(Arc::new(file_format));

    let table_path = format!("file://{}", file_path.to_str().unwrap());

    let _ = ctx
        .register_listing_table(
            "encrypted_parquet_table",
            &table_path,
            listing_options.clone(),
            None,
            None,
        )
        .await?;

    let df = ctx.sql("SELECT * FROM encrypted_parquet_table").await?;
    let mut batch_stream = df.execute_stream().await?;
    println!("Reading encrypted Parquet as a RecordBatch stream");
    while let Some(batch) = batch_stream.next().await {
        let batch = batch?;
        println!("Read batch with {} rows", batch.num_rows());
    }

    println!("Finished reading");
    Ok(())
}

/// Write an encrypted Parquet file using only SQL syntax with string configuration
async fn write_encrypted_with_sql(ctx: &SessionContext, tmpdir: &TempDir) -> Result<()> {
    let output_path = tmpdir.path().to_str().unwrap();
    let query = format!(
        "COPY test_data \
        TO '{output_path}' \
        STORED AS parquet
        OPTIONS (\
            'format.crypto.factory_id' '{ENCRYPTION_FACTORY_ID}', \
            'format.crypto.factory_options.footer_key_id' 'kf' \
        )"
    );
    let _ = ctx.sql(&query).await?.collect().await?;

    println!("Encrypted Parquet written to {:?}", tmpdir.path());
    Ok(())
}

/// Read from an encrypted Parquet file using only the SQL API and string based configuration
async fn read_encrypted_with_sql(
    ctx: &SessionContext,
    file_path: &std::path::Path,
) -> Result<()> {
    let file_path = file_path.to_str().unwrap();
    let ddl = format!(
        "CREATE EXTERNAL TABLE encrypted_parquet_table_2 \
        STORED AS PARQUET LOCATION '{file_path}' OPTIONS (\
        'format.crypto.factory_id' '{ENCRYPTION_FACTORY_ID}' \
        )"
    );
    ctx.sql(&ddl).await?;
    let df = ctx.sql("SELECT * FROM encrypted_parquet_table_2").await?;
    let mut batch_stream = df.execute_stream().await?;

    println!("Reading encrypted Parquet as a RecordBatch stream");
    while let Some(batch) = batch_stream.next().await {
        let batch = batch?;
        println!("Read batch with {} rows", batch.num_rows());
    }
    println!("Finished reading");
    Ok(())
}

// Options used to configure our example encryption factory
extensions_options! {
    struct KmsEncryptionConfig {
        pub footer_key_id: String, default = "".to_owned()
    }
}

/// Wrapper type around `CryptoFactory` to allow implementing the `EncryptionFactory` trait
struct KmsEncryptionFactory {
    crypto_factory: CryptoFactory,
}

impl std::fmt::Debug for KmsEncryptionFactory {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KmsEncryptionFactory").finish()
    }
}

/// `EncryptionFactory` is a trait defined by DataFusion that allows generating
/// file encryption and decryption properties.
impl EncryptionFactory for KmsEncryptionFactory {
    type Options = KmsEncryptionConfig;

    /// Generate file encryption properties to use when writing a Parquet file.
    /// The `FileSinkConfig` is provided so that the schema may be used to dynamically configure
    /// per-column encryption keys.
    /// Because `FileSinkConfig` can represent multiple output files, we also provide a
    /// single file path so that external key material may be used (where key metadata is
    /// stored in a JSON file alongside Parquet files).
    fn get_file_encryption_properties(
        &self,
        config: &KmsEncryptionConfig,
        _schema: &SchemaRef,
        _file_path: &Path,
    ) -> Result<Option<FileEncryptionProperties>> {
        if config.footer_key_id.is_empty() {
            return Err(DataFusionError::Configuration(
                "Footer key id for encryption is not set".to_owned(),
            ));
        };
        // We could configure per-column keys using the provided schema,
        // but for simplicity this example uses uniform encryption.
        let encryption_config =
            EncryptionConfiguration::builder(config.footer_key_id.clone()).build()?;
        // Similarly, the KMS connection could be configured from the options if needed, but this
        // example just uses the default options.
        let kms_config = Arc::new(KmsConnectionConfig::default());
        Ok(Some(self.crypto_factory.file_encryption_properties(
            kms_config,
            &encryption_config,
        )?))
    }

    /// Generate file decryption properties to use when reading a Parquet file.
    /// The `file_path` needs to be known to support encryption factories that use external key material.
    fn get_file_decryption_properties(
        &self,
        _config: &KmsEncryptionConfig,
        _file_path: &Path,
    ) -> Result<Option<FileDecryptionProperties>> {
        let decryption_config = DecryptionConfiguration::builder().build();
        let kms_config = Arc::new(KmsConnectionConfig::default());
        Ok(Some(self.crypto_factory.file_decryption_properties(
            kms_config,
            decryption_config,
        )?))
    }
}
