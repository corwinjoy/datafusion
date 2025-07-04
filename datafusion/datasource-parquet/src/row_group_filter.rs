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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::{ParquetAccessPlan, ParquetFileMetrics};
use arrow::array::{ArrayRef, BooleanArray};
use arrow::datatypes::Schema;
use datafusion_common::pruning::PruningStatistics;
use datafusion_common::{Column, Result, ScalarValue};
use datafusion_datasource::FileRange;
use datafusion_pruning::PruningPredicate;
use parquet::arrow::arrow_reader::statistics::StatisticsConverter;
use parquet::arrow::parquet_column;
use parquet::basic::Type;
use parquet::data_type::Decimal;
use parquet::schema::types::SchemaDescriptor;
use parquet::{
    arrow::{async_reader::AsyncFileReader, ParquetRecordBatchStreamBuilder},
    bloom_filter::Sbbf,
    file::metadata::RowGroupMetaData,
};

/// Reduces the [`ParquetAccessPlan`] based on row group level metadata.
///
/// This struct implements the various types of pruning that are applied to a
/// set of row groups within a parquet file, progressively narrowing down the
/// set of row groups (and ranges/selections within those row groups) that
/// should be scanned, based on the available metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct RowGroupAccessPlanFilter {
    /// which row groups should be accessed
    access_plan: ParquetAccessPlan,
}

impl RowGroupAccessPlanFilter {
    /// Create a new `RowGroupPlanBuilder` for pruning out the groups to scan
    /// based on metadata and statistics
    pub fn new(access_plan: ParquetAccessPlan) -> Self {
        Self { access_plan }
    }

    /// Return true if there are no row groups
    pub fn is_empty(&self) -> bool {
        self.access_plan.is_empty()
    }

    /// Returns the inner access plan
    pub fn build(self) -> ParquetAccessPlan {
        self.access_plan
    }

    /// Prune remaining row groups to only those  within the specified range.
    ///
    /// Updates this set to mark row groups that should not be scanned
    ///
    /// # Panics
    /// if `groups.len() != self.len()`
    pub fn prune_by_range(&mut self, groups: &[RowGroupMetaData], range: &FileRange) {
        assert_eq!(groups.len(), self.access_plan.len());
        for (idx, metadata) in groups.iter().enumerate() {
            if !self.access_plan.should_scan(idx) {
                continue;
            }

            // Skip the row group if the first dictionary/data page are not
            // within the range.
            //
            // note don't use the location of metadata
            // <https://github.com/apache/datafusion/issues/5995>
            let col = metadata.column(0);
            let offset = col
                .dictionary_page_offset()
                .unwrap_or_else(|| col.data_page_offset());
            if !range.contains(offset) {
                self.access_plan.skip(idx);
            }
        }
    }
    /// Prune remaining row groups using min/max/null_count statistics and
    /// the [`PruningPredicate`] to determine if the predicate can not be true.
    ///
    /// Updates this set to mark row groups that should not be scanned
    ///
    /// Note: This method currently ignores ColumnOrder
    /// <https://github.com/apache/datafusion/issues/8335>
    ///
    /// # Panics
    /// if `groups.len() != self.len()`
    pub fn prune_by_statistics(
        &mut self,
        arrow_schema: &Schema,
        parquet_schema: &SchemaDescriptor,
        groups: &[RowGroupMetaData],
        predicate: &PruningPredicate,
        metrics: &ParquetFileMetrics,
    ) {
        // scoped timer updates on drop
        let _timer_guard = metrics.statistics_eval_time.timer();

        assert_eq!(groups.len(), self.access_plan.len());
        // Indexes of row groups still to scan
        let row_group_indexes = self.access_plan.row_group_indexes();
        let row_group_metadatas = row_group_indexes
            .iter()
            .map(|&i| &groups[i])
            .collect::<Vec<_>>();

        let pruning_stats = RowGroupPruningStatistics {
            parquet_schema,
            row_group_metadatas,
            arrow_schema,
        };

        // try to prune the row groups in a single call
        match predicate.prune(&pruning_stats) {
            Ok(values) => {
                // values[i] is false means the predicate could not be true for row group i
                for (idx, &value) in row_group_indexes.iter().zip(values.iter()) {
                    if !value {
                        self.access_plan.skip(*idx);
                        metrics.row_groups_pruned_statistics.add(1);
                    } else {
                        metrics.row_groups_matched_statistics.add(1);
                    }
                }
            }
            // stats filter array could not be built, so we can't prune
            Err(e) => {
                log::debug!("Error evaluating row group predicate values {e}");
                metrics.predicate_evaluation_errors.add(1);
            }
        }
    }

    /// Prune remaining row groups using available bloom filters and the
    /// [`PruningPredicate`].
    ///
    /// Updates this set with row groups that should not be scanned
    ///
    /// # Panics
    /// if the builder does not have the same number of row groups as this set
    pub async fn prune_by_bloom_filters<T: AsyncFileReader + Send + 'static>(
        &mut self,
        arrow_schema: &Schema,
        builder: &mut ParquetRecordBatchStreamBuilder<T>,
        predicate: &PruningPredicate,
        metrics: &ParquetFileMetrics,
    ) {
        // scoped timer updates on drop
        let _timer_guard = metrics.bloom_filter_eval_time.timer();

        assert_eq!(builder.metadata().num_row_groups(), self.access_plan.len());
        for idx in 0..self.access_plan.len() {
            if !self.access_plan.should_scan(idx) {
                continue;
            }

            // Attempt to find bloom filters for filtering this row group
            let literal_columns = predicate.literal_columns();
            let mut column_sbbf = HashMap::with_capacity(literal_columns.len());

            for column_name in literal_columns {
                let Some((column_idx, _field)) =
                    parquet_column(builder.parquet_schema(), arrow_schema, &column_name)
                else {
                    continue;
                };

                let bf = match builder
                    .get_row_group_column_bloom_filter(idx, column_idx)
                    .await
                {
                    Ok(Some(bf)) => bf,
                    Ok(None) => continue, // no bloom filter for this column
                    Err(e) => {
                        log::debug!("Ignoring error reading bloom filter: {e}");
                        metrics.predicate_evaluation_errors.add(1);
                        continue;
                    }
                };
                let physical_type =
                    builder.parquet_schema().column(column_idx).physical_type();

                column_sbbf.insert(column_name.to_string(), (bf, physical_type));
            }

            let stats = BloomFilterStatistics { column_sbbf };

            // Can this group be pruned?
            let prune_group = match predicate.prune(&stats) {
                Ok(values) => !values[0],
                Err(e) => {
                    log::debug!(
                        "Error evaluating row group predicate on bloom filter: {e}"
                    );
                    metrics.predicate_evaluation_errors.add(1);
                    false
                }
            };

            if prune_group {
                metrics.row_groups_pruned_bloom_filter.add(1);
                self.access_plan.skip(idx)
            } else if !stats.column_sbbf.is_empty() {
                metrics.row_groups_matched_bloom_filter.add(1);
            }
        }
    }
}
/// Implements [`PruningStatistics`] for Parquet Split Block Bloom Filters (SBBF)
struct BloomFilterStatistics {
    /// Maps column name to the parquet bloom filter and parquet physical type
    column_sbbf: HashMap<String, (Sbbf, Type)>,
}

impl BloomFilterStatistics {
    /// Helper function for checking if [`Sbbf`] filter contains [`ScalarValue`].
    ///
    /// In case the type of scalar is not supported, returns `true`, assuming that the
    /// value may be present.
    fn check_scalar(sbbf: &Sbbf, value: &ScalarValue, parquet_type: &Type) -> bool {
        match value {
            ScalarValue::Utf8(Some(v))
            | ScalarValue::Utf8View(Some(v))
            | ScalarValue::LargeUtf8(Some(v)) => sbbf.check(&v.as_str()),
            ScalarValue::Binary(Some(v))
            | ScalarValue::BinaryView(Some(v))
            | ScalarValue::LargeBinary(Some(v)) => sbbf.check(v),
            ScalarValue::FixedSizeBinary(_size, Some(v)) => sbbf.check(v),
            ScalarValue::Boolean(Some(v)) => sbbf.check(v),
            ScalarValue::Float64(Some(v)) => sbbf.check(v),
            ScalarValue::Float32(Some(v)) => sbbf.check(v),
            ScalarValue::Int64(Some(v)) => sbbf.check(v),
            ScalarValue::Int32(Some(v)) => sbbf.check(v),
            ScalarValue::UInt64(Some(v)) => sbbf.check(v),
            ScalarValue::UInt32(Some(v)) => sbbf.check(v),
            ScalarValue::Decimal128(Some(v), p, s) => match parquet_type {
                Type::INT32 => {
                    //https://github.com/apache/parquet-format/blob/eb4b31c1d64a01088d02a2f9aefc6c17c54cc6fc/Encodings.md?plain=1#L35-L42
                    // All physical type  are little-endian
                    if *p > 9 {
                        //DECIMAL can be used to annotate the following types:
                        //
                        // int32: for 1 <= precision <= 9
                        // int64: for 1 <= precision <= 18
                        return true;
                    }
                    let b = (*v as i32).to_le_bytes();
                    // Use Decimal constructor after https://github.com/apache/arrow-rs/issues/5325
                    let decimal = Decimal::Int32 {
                        value: b,
                        precision: *p as i32,
                        scale: *s as i32,
                    };
                    sbbf.check(&decimal)
                }
                Type::INT64 => {
                    if *p > 18 {
                        return true;
                    }
                    let b = (*v as i64).to_le_bytes();
                    let decimal = Decimal::Int64 {
                        value: b,
                        precision: *p as i32,
                        scale: *s as i32,
                    };
                    sbbf.check(&decimal)
                }
                Type::FIXED_LEN_BYTE_ARRAY => {
                    // keep with from_bytes_to_i128
                    let b = v.to_be_bytes().to_vec();
                    // Use Decimal constructor after https://github.com/apache/arrow-rs/issues/5325
                    let decimal = Decimal::Bytes {
                        value: b.into(),
                        precision: *p as i32,
                        scale: *s as i32,
                    };
                    sbbf.check(&decimal)
                }
                _ => true,
            },
            ScalarValue::Dictionary(_, inner) => {
                BloomFilterStatistics::check_scalar(sbbf, inner, parquet_type)
            }
            _ => true,
        }
    }
}

impl PruningStatistics for BloomFilterStatistics {
    fn min_values(&self, _column: &Column) -> Option<ArrayRef> {
        None
    }

    fn max_values(&self, _column: &Column) -> Option<ArrayRef> {
        None
    }

    fn num_containers(&self) -> usize {
        1
    }

    fn null_counts(&self, _column: &Column) -> Option<ArrayRef> {
        None
    }

    fn row_counts(&self, _column: &Column) -> Option<ArrayRef> {
        None
    }

    /// Use bloom filters to determine if we are sure this column can not
    /// possibly contain `values`
    ///
    /// The `contained` API returns false if the bloom filters knows that *ALL*
    /// of the values in a column are not present.
    fn contained(
        &self,
        column: &Column,
        values: &HashSet<ScalarValue>,
    ) -> Option<BooleanArray> {
        let (sbbf, parquet_type) = self.column_sbbf.get(column.name.as_str())?;

        // Bloom filters are probabilistic data structures that can return false
        // positives (i.e. it might return true even if the value is not
        // present) however, the bloom filter will return `false` if the value is
        // definitely not present.

        let known_not_present = values
            .iter()
            .map(|value| BloomFilterStatistics::check_scalar(sbbf, value, parquet_type))
            // The row group doesn't contain any of the values if
            // all the checks are false
            .all(|v| !v);

        let contains = if known_not_present {
            Some(false)
        } else {
            // Given the bloom filter is probabilistic, we can't be sure that
            // the row group actually contains the values. Return `None` to
            // indicate this uncertainty
            None
        };

        Some(BooleanArray::from(vec![contains]))
    }
}

/// Wraps a slice of [`RowGroupMetaData`] in a way that implements [`PruningStatistics`]
struct RowGroupPruningStatistics<'a> {
    parquet_schema: &'a SchemaDescriptor,
    row_group_metadatas: Vec<&'a RowGroupMetaData>,
    arrow_schema: &'a Schema,
}

impl<'a> RowGroupPruningStatistics<'a> {
    /// Return an iterator over the row group metadata
    fn metadata_iter(&'a self) -> impl Iterator<Item = &'a RowGroupMetaData> + 'a {
        self.row_group_metadatas.iter().copied()
    }

    fn statistics_converter<'b>(
        &'a self,
        column: &'b Column,
    ) -> Result<StatisticsConverter<'a>> {
        Ok(StatisticsConverter::try_new(
            &column.name,
            self.arrow_schema,
            self.parquet_schema,
        )?)
    }
}

impl PruningStatistics for RowGroupPruningStatistics<'_> {
    fn min_values(&self, column: &Column) -> Option<ArrayRef> {
        self.statistics_converter(column)
            .and_then(|c| Ok(c.row_group_mins(self.metadata_iter())?))
            .ok()
    }

    fn max_values(&self, column: &Column) -> Option<ArrayRef> {
        self.statistics_converter(column)
            .and_then(|c| Ok(c.row_group_maxes(self.metadata_iter())?))
            .ok()
    }

    fn num_containers(&self) -> usize {
        self.row_group_metadatas.len()
    }

    fn null_counts(&self, column: &Column) -> Option<ArrayRef> {
        self.statistics_converter(column)
            .and_then(|c| Ok(c.row_group_null_counts(self.metadata_iter())?))
            .ok()
            .map(|counts| Arc::new(counts) as ArrayRef)
    }

    fn row_counts(&self, column: &Column) -> Option<ArrayRef> {
        // row counts are the same for all columns in a row group
        self.statistics_converter(column)
            .and_then(|c| Ok(c.row_group_row_counts(self.metadata_iter())?))
            .ok()
            .flatten()
            .map(|counts| Arc::new(counts) as ArrayRef)
    }

    fn contained(
        &self,
        _column: &Column,
        _values: &HashSet<ScalarValue>,
    ) -> Option<BooleanArray> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Rem;
    use std::sync::Arc;

    use super::*;
    use crate::reader::ParquetFileReader;

    use arrow::datatypes::DataType::Decimal128;
    use arrow::datatypes::{DataType, Field};
    use datafusion_common::Result;
    use datafusion_expr::{cast, col, lit, Expr};
    use datafusion_physical_expr::planner::logical2physical;
    use datafusion_physical_plan::metrics::ExecutionPlanMetricsSet;
    use parquet::arrow::async_reader::ParquetObjectReader;
    use parquet::arrow::ArrowSchemaConverter;
    use parquet::basic::LogicalType;
    use parquet::data_type::{ByteArray, FixedLenByteArray};
    use parquet::file::metadata::ColumnChunkMetaData;
    use parquet::{
        basic::Type as PhysicalType, file::statistics::Statistics as ParquetStatistics,
        schema::types::SchemaDescPtr,
    };

    struct PrimitiveTypeField {
        name: &'static str,
        physical_ty: PhysicalType,
        logical_ty: Option<LogicalType>,
        precision: Option<i32>,
        scale: Option<i32>,
        byte_len: Option<i32>,
    }

    impl PrimitiveTypeField {
        fn new(name: &'static str, physical_ty: PhysicalType) -> Self {
            Self {
                name,
                physical_ty,
                logical_ty: None,
                precision: None,
                scale: None,
                byte_len: None,
            }
        }

        fn with_logical_type(mut self, logical_type: LogicalType) -> Self {
            self.logical_ty = Some(logical_type);
            self
        }

        fn with_precision(mut self, precision: i32) -> Self {
            self.precision = Some(precision);
            self
        }

        fn with_scale(mut self, scale: i32) -> Self {
            self.scale = Some(scale);
            self
        }

        fn with_byte_len(mut self, byte_len: i32) -> Self {
            self.byte_len = Some(byte_len);
            self
        }
    }

    #[test]
    fn row_group_pruning_predicate_simple_expr() {
        use datafusion_expr::{col, lit};
        // int > 1 => c1_max > 1
        let schema =
            Arc::new(Schema::new(vec![Field::new("c1", DataType::Int32, false)]));
        let expr = col("c1").gt(lit(15));
        let expr = logical2physical(&expr, &schema);
        let pruning_predicate = PruningPredicate::try_new(expr, schema.clone()).unwrap();

        let field = PrimitiveTypeField::new("c1", PhysicalType::INT32);
        let schema_descr = get_test_schema_descr(vec![field]);
        let rgm1 = get_row_group_meta_data(
            &schema_descr,
            vec![ParquetStatistics::int32(
                Some(1),
                Some(10),
                None,
                Some(0),
                false,
            )],
        );
        let rgm2 = get_row_group_meta_data(
            &schema_descr,
            vec![ParquetStatistics::int32(
                Some(11),
                Some(20),
                None,
                Some(0),
                false,
            )],
        );

        let metrics = parquet_file_metrics();
        let mut row_groups = RowGroupAccessPlanFilter::new(ParquetAccessPlan::new_all(2));
        row_groups.prune_by_statistics(
            &schema,
            &schema_descr,
            &[rgm1, rgm2],
            &pruning_predicate,
            &metrics,
        );
        assert_pruned(row_groups, ExpectedPruning::Some(vec![1]))
    }

    #[test]
    fn row_group_pruning_predicate_missing_stats() {
        use datafusion_expr::{col, lit};
        // int > 1 => c1_max > 1
        let schema =
            Arc::new(Schema::new(vec![Field::new("c1", DataType::Int32, false)]));
        let expr = col("c1").gt(lit(15));
        let expr = logical2physical(&expr, &schema);
        let pruning_predicate = PruningPredicate::try_new(expr, schema.clone()).unwrap();

        let field = PrimitiveTypeField::new("c1", PhysicalType::INT32);
        let schema_descr = get_test_schema_descr(vec![field]);
        let rgm1 = get_row_group_meta_data(
            &schema_descr,
            vec![ParquetStatistics::int32(None, None, None, Some(0), false)],
        );
        let rgm2 = get_row_group_meta_data(
            &schema_descr,
            vec![ParquetStatistics::int32(
                Some(11),
                Some(20),
                None,
                Some(0),
                false,
            )],
        );
        let metrics = parquet_file_metrics();
        // missing statistics for first row group mean that the result from the predicate expression
        // is null / undefined so the first row group can't be filtered out
        let mut row_groups = RowGroupAccessPlanFilter::new(ParquetAccessPlan::new_all(2));
        row_groups.prune_by_statistics(
            &schema,
            &schema_descr,
            &[rgm1, rgm2],
            &pruning_predicate,
            &metrics,
        );
        assert_pruned(row_groups, ExpectedPruning::None);
    }

    #[test]
    fn row_group_pruning_predicate_partial_expr() {
        use datafusion_expr::{col, lit};
        // test row group predicate with partially supported expression
        // (int > 1) and ((int % 2) = 0) => c1_max > 1 and true
        let schema = Arc::new(Schema::new(vec![
            Field::new("c1", DataType::Int32, false),
            Field::new("c2", DataType::Int32, false),
        ]));
        let expr = col("c1").gt(lit(15)).and(col("c2").rem(lit(2)).eq(lit(0)));
        let expr = logical2physical(&expr, &schema);
        let pruning_predicate = PruningPredicate::try_new(expr, schema.clone()).unwrap();

        let schema_descr = get_test_schema_descr(vec![
            PrimitiveTypeField::new("c1", PhysicalType::INT32),
            PrimitiveTypeField::new("c2", PhysicalType::INT32),
        ]);
        let rgm1 = get_row_group_meta_data(
            &schema_descr,
            vec![
                ParquetStatistics::int32(Some(1), Some(10), None, Some(0), false),
                ParquetStatistics::int32(Some(1), Some(10), None, Some(0), false),
            ],
        );
        let rgm2 = get_row_group_meta_data(
            &schema_descr,
            vec![
                ParquetStatistics::int32(Some(11), Some(20), None, Some(0), false),
                ParquetStatistics::int32(Some(11), Some(20), None, Some(0), false),
            ],
        );

        let metrics = parquet_file_metrics();
        let groups = &[rgm1, rgm2];
        // the first row group is still filtered out because the predicate expression can be partially evaluated
        // when conditions are joined using AND
        let mut row_groups = RowGroupAccessPlanFilter::new(ParquetAccessPlan::new_all(2));
        row_groups.prune_by_statistics(
            &schema,
            &schema_descr,
            groups,
            &pruning_predicate,
            &metrics,
        );
        assert_pruned(row_groups, ExpectedPruning::Some(vec![1]));

        // if conditions in predicate are joined with OR and an unsupported expression is used
        // this bypasses the entire predicate expression and no row groups are filtered out
        let expr = col("c1").gt(lit(15)).or(col("c2").rem(lit(2)).eq(lit(0)));
        let expr = logical2physical(&expr, &schema);
        let pruning_predicate = PruningPredicate::try_new(expr, schema.clone()).unwrap();

        // if conditions in predicate are joined with OR and an unsupported expression is used
        // this bypasses the entire predicate expression and no row groups are filtered out
        let mut row_groups = RowGroupAccessPlanFilter::new(ParquetAccessPlan::new_all(2));
        row_groups.prune_by_statistics(
            &schema,
            &schema_descr,
            groups,
            &pruning_predicate,
            &metrics,
        );
        assert_pruned(row_groups, ExpectedPruning::None);
    }

    #[test]
    fn row_group_pruning_predicate_file_schema() {
        use datafusion_expr::{col, lit};
        // test row group predicate when file schema is different than table schema
        // c1 > 0
        let table_schema = Arc::new(Schema::new(vec![
            Field::new("c1", DataType::Int32, false),
            Field::new("c2", DataType::Int32, false),
        ]));
        let expr = col("c1").gt(lit(0));
        let expr = logical2physical(&expr, &table_schema);
        let pruning_predicate =
            PruningPredicate::try_new(expr, table_schema.clone()).unwrap();

        // Model a file schema's column order c2 then c1, which is the opposite
        // of the table schema
        let file_schema = Arc::new(Schema::new(vec![
            Field::new("c2", DataType::Int32, false),
            Field::new("c1", DataType::Int32, false),
        ]));
        let schema_descr = get_test_schema_descr(vec![
            PrimitiveTypeField::new("c2", PhysicalType::INT32),
            PrimitiveTypeField::new("c1", PhysicalType::INT32),
        ]);
        // rg1 has c2 less than zero, c1 greater than zero
        let rgm1 = get_row_group_meta_data(
            &schema_descr,
            vec![
                ParquetStatistics::int32(Some(-10), Some(-1), None, Some(0), false), // c2
                ParquetStatistics::int32(Some(1), Some(10), None, Some(0), false),
            ],
        );
        // rg1 has c2 greater than zero, c1 less than zero
        let rgm2 = get_row_group_meta_data(
            &schema_descr,
            vec![
                ParquetStatistics::int32(Some(1), Some(10), None, Some(0), false),
                ParquetStatistics::int32(Some(-10), Some(-1), None, Some(0), false),
            ],
        );

        let metrics = parquet_file_metrics();
        let groups = &[rgm1, rgm2];
        // the first row group should be left because c1 is greater than zero
        // the second should be filtered out because c1 is less than zero
        let mut row_groups = RowGroupAccessPlanFilter::new(ParquetAccessPlan::new_all(2));
        row_groups.prune_by_statistics(
            &file_schema,
            &schema_descr,
            groups,
            &pruning_predicate,
            &metrics,
        );
        assert_pruned(row_groups, ExpectedPruning::Some(vec![0]));
    }

    fn gen_row_group_meta_data_for_pruning_predicate() -> Vec<RowGroupMetaData> {
        let schema_descr = get_test_schema_descr(vec![
            PrimitiveTypeField::new("c1", PhysicalType::INT32),
            PrimitiveTypeField::new("c2", PhysicalType::BOOLEAN),
        ]);
        let rgm1 = get_row_group_meta_data(
            &schema_descr,
            vec![
                ParquetStatistics::int32(Some(1), Some(10), None, Some(0), false),
                ParquetStatistics::boolean(Some(false), Some(true), None, Some(0), false),
            ],
        );
        let rgm2 = get_row_group_meta_data(
            &schema_descr,
            vec![
                ParquetStatistics::int32(Some(11), Some(20), None, Some(0), false),
                ParquetStatistics::boolean(Some(false), Some(true), None, Some(1), false),
            ],
        );
        vec![rgm1, rgm2]
    }

    #[test]
    fn row_group_pruning_predicate_null_expr() {
        use datafusion_expr::{col, lit};
        // int > 1 and IsNull(bool) => c1_max > 1 and bool_null_count > 0
        let schema = Arc::new(Schema::new(vec![
            Field::new("c1", DataType::Int32, false),
            Field::new("c2", DataType::Boolean, false),
        ]));
        let schema_descr = ArrowSchemaConverter::new().convert(&schema).unwrap();
        let expr = col("c1").gt(lit(15)).and(col("c2").is_null());
        let expr = logical2physical(&expr, &schema);
        let pruning_predicate = PruningPredicate::try_new(expr, schema.clone()).unwrap();
        let groups = gen_row_group_meta_data_for_pruning_predicate();

        let metrics = parquet_file_metrics();
        // First row group was filtered out because it contains no null value on "c2".
        let mut row_groups = RowGroupAccessPlanFilter::new(ParquetAccessPlan::new_all(2));
        row_groups.prune_by_statistics(
            &schema,
            &schema_descr,
            &groups,
            &pruning_predicate,
            &metrics,
        );
        assert_pruned(row_groups, ExpectedPruning::Some(vec![1]));
    }

    #[test]
    fn row_group_pruning_predicate_eq_null_expr() {
        use datafusion_expr::{col, lit};
        // test row group predicate with an unknown (Null) expr
        //
        // int > 1 and bool = NULL => c1_max > 1 and null
        let schema = Arc::new(Schema::new(vec![
            Field::new("c1", DataType::Int32, false),
            Field::new("c2", DataType::Boolean, false),
        ]));
        let schema_descr = ArrowSchemaConverter::new().convert(&schema).unwrap();
        let expr = col("c1")
            .gt(lit(15))
            .and(col("c2").eq(lit(ScalarValue::Boolean(None))));
        let expr = logical2physical(&expr, &schema);
        let pruning_predicate = PruningPredicate::try_new(expr, schema.clone()).unwrap();
        let groups = gen_row_group_meta_data_for_pruning_predicate();

        let metrics = parquet_file_metrics();
        // bool = NULL always evaluates to NULL (and thus will not
        // pass predicates. Ideally these should both be false
        let mut row_groups =
            RowGroupAccessPlanFilter::new(ParquetAccessPlan::new_all(groups.len()));
        row_groups.prune_by_statistics(
            &schema,
            &schema_descr,
            &groups,
            &pruning_predicate,
            &metrics,
        );
        assert_pruned(row_groups, ExpectedPruning::Some(vec![1]));
    }

    #[test]
    fn row_group_pruning_predicate_decimal_type() {
        // For the decimal data type, parquet can use `INT32`, `INT64`, `BYTE_ARRAY`, `FIXED_LENGTH_BYTE_ARRAY` to
        // store the data.
        // In this case, construct four types of statistics to filtered with the decimal predication.

        // INT32: c1 > 5, the c1 is decimal(9,2)
        // The type of scalar value if decimal(9,2), don't need to do cast
        let schema =
            Arc::new(Schema::new(vec![Field::new("c1", Decimal128(9, 2), false)]));
        let field = PrimitiveTypeField::new("c1", PhysicalType::INT32)
            .with_logical_type(LogicalType::Decimal {
                scale: 2,
                precision: 9,
            })
            .with_scale(2)
            .with_precision(9);
        let schema_descr = get_test_schema_descr(vec![field]);
        let expr = col("c1").gt(lit(ScalarValue::Decimal128(Some(500), 9, 2)));
        let expr = logical2physical(&expr, &schema);
        let pruning_predicate = PruningPredicate::try_new(expr, schema.clone()).unwrap();
        let rgm1 = get_row_group_meta_data(
            &schema_descr,
            // [1.00, 6.00]
            // c1 > 5, this row group will be included in the results.
            vec![ParquetStatistics::int32(
                Some(100),
                Some(600),
                None,
                Some(0),
                false,
            )],
        );
        let rgm2 = get_row_group_meta_data(
            &schema_descr,
            // [0.1, 0.2]
            // c1 > 5, this row group will not be included in the results.
            vec![ParquetStatistics::int32(
                Some(10),
                Some(20),
                None,
                Some(0),
                false,
            )],
        );
        let rgm3 = get_row_group_meta_data(
            &schema_descr,
            // [1, None]
            // c1 > 5, this row group can not be filtered out, so will be included in the results.
            vec![ParquetStatistics::int32(
                Some(100),
                None,
                None,
                Some(0),
                false,
            )],
        );
        let metrics = parquet_file_metrics();
        let mut row_groups = RowGroupAccessPlanFilter::new(ParquetAccessPlan::new_all(3));
        row_groups.prune_by_statistics(
            &schema,
            &schema_descr,
            &[rgm1, rgm2, rgm3],
            &pruning_predicate,
            &metrics,
        );
        assert_pruned(row_groups, ExpectedPruning::Some(vec![0, 2]));
    }

    #[test]
    fn row_group_pruning_predicate_decimal_type2() {
        // INT32: c1 > 5, but parquet decimal type has different precision or scale to arrow decimal
        // The c1 type is decimal(9,0) in the parquet file, and the type of scalar is decimal(5,2).
        // We should convert all type to the coercion type, which is decimal(11,2)
        // The decimal of arrow is decimal(5,2), the decimal of parquet is decimal(9,0)
        let schema =
            Arc::new(Schema::new(vec![Field::new("c1", Decimal128(9, 0), false)]));

        let field = PrimitiveTypeField::new("c1", PhysicalType::INT32)
            .with_logical_type(LogicalType::Decimal {
                scale: 0,
                precision: 9,
            })
            .with_scale(0)
            .with_precision(9);
        let schema_descr = get_test_schema_descr(vec![field]);
        let expr = cast(col("c1"), Decimal128(11, 2)).gt(cast(
            lit(ScalarValue::Decimal128(Some(500), 5, 2)),
            Decimal128(11, 2),
        ));
        let expr = logical2physical(&expr, &schema);
        let pruning_predicate = PruningPredicate::try_new(expr, schema.clone()).unwrap();
        let rgm1 = get_row_group_meta_data(
            &schema_descr,
            // [100, 600]
            // c1 > 5, this row group will be included in the results.
            vec![ParquetStatistics::int32(
                Some(100),
                Some(600),
                None,
                Some(0),
                false,
            )],
        );
        let rgm2 = get_row_group_meta_data(
            &schema_descr,
            // [10, 20]
            // c1 > 5, this row group will be included in the results.
            vec![ParquetStatistics::int32(
                Some(10),
                Some(20),
                None,
                Some(0),
                false,
            )],
        );
        let rgm3 = get_row_group_meta_data(
            &schema_descr,
            // [0, 2]
            // c1 > 5, this row group will not be included in the results.
            vec![ParquetStatistics::int32(
                Some(0),
                Some(2),
                None,
                Some(0),
                false,
            )],
        );
        let rgm4 = get_row_group_meta_data(
            &schema_descr,
            // [None, 2]
            // c1 > 5, this row group will also not be included in the results
            // (the min value is unknown, but the max value is 2, so no values can be greater than 5)
            vec![ParquetStatistics::int32(
                None,
                Some(2),
                None,
                Some(0),
                false,
            )],
        );
        let rgm5 = get_row_group_meta_data(
            &schema_descr,
            // [2, None]
            // c1 > 5, this row group must be included
            // (the min value is 2, but the max value is unknown, so it may have values greater than 5)
            vec![ParquetStatistics::int32(
                Some(2),
                None,
                None,
                Some(0),
                false,
            )],
        );
        let metrics = parquet_file_metrics();
        let mut row_groups = RowGroupAccessPlanFilter::new(ParquetAccessPlan::new_all(5));
        row_groups.prune_by_statistics(
            &schema,
            &schema_descr,
            &[rgm1, rgm2, rgm3, rgm4, rgm5],
            &pruning_predicate,
            &metrics,
        );
        assert_pruned(row_groups, ExpectedPruning::Some(vec![0, 1, 4]));
    }
    #[test]
    fn row_group_pruning_predicate_decimal_type3() {
        // INT64: c1 < 5, the c1 is decimal(18,2)
        let schema = Arc::new(Schema::new(vec![Field::new(
            "c1",
            Decimal128(18, 2),
            false,
        )]));
        let field = PrimitiveTypeField::new("c1", PhysicalType::INT64)
            .with_logical_type(LogicalType::Decimal {
                scale: 2,
                precision: 18,
            })
            .with_scale(2)
            .with_precision(18);
        let schema_descr = get_test_schema_descr(vec![field]);
        let expr = col("c1").lt(lit(ScalarValue::Decimal128(Some(500), 18, 2)));
        let expr = logical2physical(&expr, &schema);
        let pruning_predicate = PruningPredicate::try_new(expr, schema.clone()).unwrap();
        let rgm1 = get_row_group_meta_data(
            &schema_descr,
            // [6.00, 8.00]
            vec![ParquetStatistics::int32(
                Some(600),
                Some(800),
                None,
                Some(0),
                false,
            )],
        );
        let rgm2 = get_row_group_meta_data(
            &schema_descr,
            // [0.1, 0.2]
            vec![ParquetStatistics::int64(
                Some(10),
                Some(20),
                None,
                Some(0),
                false,
            )],
        );
        let rgm3 = get_row_group_meta_data(
            &schema_descr,
            // [0.1, 0.2]
            vec![ParquetStatistics::int64(None, None, None, Some(0), false)],
        );
        let metrics = parquet_file_metrics();
        let mut row_groups = RowGroupAccessPlanFilter::new(ParquetAccessPlan::new_all(3));
        row_groups.prune_by_statistics(
            &schema,
            &schema_descr,
            &[rgm1, rgm2, rgm3],
            &pruning_predicate,
            &metrics,
        );
        assert_pruned(row_groups, ExpectedPruning::Some(vec![1, 2]));
    }
    #[test]
    fn row_group_pruning_predicate_decimal_type4() {
        // FIXED_LENGTH_BYTE_ARRAY: c1 = decimal128(100000, 28, 3), the c1 is decimal(18,2)
        // the type of parquet is decimal(18,2)
        let schema = Arc::new(Schema::new(vec![Field::new(
            "c1",
            Decimal128(18, 2),
            false,
        )]));
        let field = PrimitiveTypeField::new("c1", PhysicalType::FIXED_LEN_BYTE_ARRAY)
            .with_logical_type(LogicalType::Decimal {
                scale: 2,
                precision: 18,
            })
            .with_scale(2)
            .with_precision(18)
            .with_byte_len(16);
        let schema_descr = get_test_schema_descr(vec![field]);
        // cast the type of c1 to decimal(28,3)
        let left = cast(col("c1"), Decimal128(28, 3));
        let expr = left.eq(lit(ScalarValue::Decimal128(Some(100000), 28, 3)));
        let expr = logical2physical(&expr, &schema);
        let pruning_predicate = PruningPredicate::try_new(expr, schema.clone()).unwrap();
        // we must use the big-endian when encode the i128 to bytes or vec[u8].
        let rgm1 = get_row_group_meta_data(
            &schema_descr,
            vec![ParquetStatistics::fixed_len_byte_array(
                // 5.00
                Some(FixedLenByteArray::from(ByteArray::from(
                    500i128.to_be_bytes().to_vec(),
                ))),
                // 80.00
                Some(FixedLenByteArray::from(ByteArray::from(
                    8000i128.to_be_bytes().to_vec(),
                ))),
                None,
                Some(0),
                false,
            )],
        );
        let rgm2 = get_row_group_meta_data(
            &schema_descr,
            vec![ParquetStatistics::fixed_len_byte_array(
                // 5.00
                Some(FixedLenByteArray::from(ByteArray::from(
                    500i128.to_be_bytes().to_vec(),
                ))),
                // 200.00
                Some(FixedLenByteArray::from(ByteArray::from(
                    20000i128.to_be_bytes().to_vec(),
                ))),
                None,
                Some(0),
                false,
            )],
        );

        let rgm3 = get_row_group_meta_data(
            &schema_descr,
            vec![ParquetStatistics::fixed_len_byte_array(
                None,
                None,
                None,
                Some(0),
                false,
            )],
        );
        let metrics = parquet_file_metrics();
        let mut row_groups = RowGroupAccessPlanFilter::new(ParquetAccessPlan::new_all(3));
        row_groups.prune_by_statistics(
            &schema,
            &schema_descr,
            &[rgm1, rgm2, rgm3],
            &pruning_predicate,
            &metrics,
        );
        assert_pruned(row_groups, ExpectedPruning::Some(vec![1, 2]));
    }
    #[test]
    fn row_group_pruning_predicate_decimal_type5() {
        // BYTE_ARRAY: c1 = decimal128(100000, 28, 3), the c1 is decimal(18,2)
        // the type of parquet is decimal(18,2)
        let schema = Arc::new(Schema::new(vec![Field::new(
            "c1",
            Decimal128(18, 2),
            false,
        )]));
        let field = PrimitiveTypeField::new("c1", PhysicalType::BYTE_ARRAY)
            .with_logical_type(LogicalType::Decimal {
                scale: 2,
                precision: 18,
            })
            .with_scale(2)
            .with_precision(18)
            .with_byte_len(16);
        let schema_descr = get_test_schema_descr(vec![field]);
        // cast the type of c1 to decimal(28,3)
        let left = cast(col("c1"), Decimal128(28, 3));
        let expr = left.eq(lit(ScalarValue::Decimal128(Some(100000), 28, 3)));
        let expr = logical2physical(&expr, &schema);
        let pruning_predicate = PruningPredicate::try_new(expr, schema.clone()).unwrap();
        // we must use the big-endian when encode the i128 to bytes or vec[u8].
        let rgm1 = get_row_group_meta_data(
            &schema_descr,
            vec![ParquetStatistics::byte_array(
                // 5.00
                Some(ByteArray::from(500i128.to_be_bytes().to_vec())),
                // 80.00
                Some(ByteArray::from(8000i128.to_be_bytes().to_vec())),
                None,
                Some(0),
                false,
            )],
        );
        let rgm2 = get_row_group_meta_data(
            &schema_descr,
            vec![ParquetStatistics::byte_array(
                // 5.00
                Some(ByteArray::from(500i128.to_be_bytes().to_vec())),
                // 200.00
                Some(ByteArray::from(20000i128.to_be_bytes().to_vec())),
                None,
                Some(0),
                false,
            )],
        );
        let rgm3 = get_row_group_meta_data(
            &schema_descr,
            vec![ParquetStatistics::byte_array(
                None,
                None,
                None,
                Some(0),
                false,
            )],
        );
        let metrics = parquet_file_metrics();
        let mut row_groups = RowGroupAccessPlanFilter::new(ParquetAccessPlan::new_all(3));
        row_groups.prune_by_statistics(
            &schema,
            &schema_descr,
            &[rgm1, rgm2, rgm3],
            &pruning_predicate,
            &metrics,
        );
        assert_pruned(row_groups, ExpectedPruning::Some(vec![1, 2]));
    }

    fn get_row_group_meta_data(
        schema_descr: &SchemaDescPtr,
        column_statistics: Vec<ParquetStatistics>,
    ) -> RowGroupMetaData {
        let mut columns = vec![];
        let number_row = 1000;
        for (i, s) in column_statistics.iter().enumerate() {
            let column = ColumnChunkMetaData::builder(schema_descr.column(i))
                .set_statistics(s.clone())
                .set_num_values(number_row)
                .build()
                .unwrap();
            columns.push(column);
        }
        RowGroupMetaData::builder(schema_descr.clone())
            .set_num_rows(number_row)
            .set_total_byte_size(2000)
            .set_column_metadata(columns)
            .build()
            .unwrap()
    }

    fn get_test_schema_descr(fields: Vec<PrimitiveTypeField>) -> SchemaDescPtr {
        use parquet::schema::types::Type as SchemaType;
        let schema_fields = fields
            .iter()
            .map(|field| {
                let mut builder =
                    SchemaType::primitive_type_builder(field.name, field.physical_ty);
                // add logical type for the parquet field
                if let Some(logical_type) = &field.logical_ty {
                    builder = builder.with_logical_type(Some(logical_type.clone()));
                }
                if let Some(precision) = field.precision {
                    builder = builder.with_precision(precision);
                }
                if let Some(scale) = field.scale {
                    builder = builder.with_scale(scale);
                }
                if let Some(byte_len) = field.byte_len {
                    builder = builder.with_length(byte_len);
                }
                Arc::new(builder.build().unwrap())
            })
            .collect::<Vec<_>>();
        let schema = SchemaType::group_type_builder("schema")
            .with_fields(schema_fields)
            .build()
            .unwrap();

        Arc::new(SchemaDescriptor::new(Arc::new(schema)))
    }

    fn parquet_file_metrics() -> ParquetFileMetrics {
        let metrics = Arc::new(ExecutionPlanMetricsSet::new());
        ParquetFileMetrics::new(0, "file.parquet", &metrics)
    }

    #[tokio::test]
    async fn test_row_group_bloom_filter_pruning_predicate_simple_expr() {
        BloomFilterTest::new_data_index_bloom_encoding_stats()
            .with_expect_all_pruned()
            // generate pruning predicate `(String = "Hello_Not_exists")`
            .run(col(r#""String""#).eq(lit("Hello_Not_Exists")))
            .await
    }

    #[tokio::test]
    async fn test_row_group_bloom_filter_pruning_predicate_multiple_expr() {
        BloomFilterTest::new_data_index_bloom_encoding_stats()
            .with_expect_all_pruned()
            // generate pruning predicate `(String = "Hello_Not_exists" OR String = "Hello_Not_exists2")`
            .run(
                lit("1").eq(lit("1")).and(
                    col(r#""String""#)
                        .eq(lit("Hello_Not_Exists"))
                        .or(col(r#""String""#).eq(lit("Hello_Not_Exists2"))),
                ),
            )
            .await
    }

    #[tokio::test]
    async fn test_row_group_bloom_filter_pruning_predicate_multiple_expr_view() {
        BloomFilterTest::new_data_index_bloom_encoding_stats()
            .with_expect_all_pruned()
            // generate pruning predicate `(String = "Hello_Not_exists" OR String = "Hello_Not_exists2")`
            .run(
                lit("1").eq(lit("1")).and(
                    col(r#""String""#)
                        .eq(Expr::Literal(
                            ScalarValue::Utf8View(Some(String::from("Hello_Not_Exists"))),
                            None,
                        ))
                        .or(col(r#""String""#).eq(Expr::Literal(
                            ScalarValue::Utf8View(Some(String::from(
                                "Hello_Not_Exists2",
                            ))),
                            None,
                        ))),
                ),
            )
            .await
    }

    #[tokio::test]
    async fn test_row_group_bloom_filter_pruning_predicate_sql_in() {
        // load parquet file
        let testdata = datafusion_common::test_util::parquet_test_data();
        let file_name = "data_index_bloom_encoding_stats.parquet";
        let path = format!("{testdata}/{file_name}");
        let data = bytes::Bytes::from(std::fs::read(path).unwrap());

        // generate pruning predicate
        let schema = Schema::new(vec![Field::new("String", DataType::Utf8, false)]);

        let expr = col(r#""String""#).in_list(
            (1..25)
                .map(|i| lit(format!("Hello_Not_Exists{i}")))
                .collect::<Vec<_>>(),
            false,
        );
        let expr = logical2physical(&expr, &schema);
        let pruning_predicate =
            PruningPredicate::try_new(expr, Arc::new(schema)).unwrap();

        let pruned_row_groups = test_row_group_bloom_filter_pruning_predicate(
            file_name,
            data,
            &pruning_predicate,
        )
        .await
        .unwrap();
        assert!(pruned_row_groups.access_plan.row_group_indexes().is_empty());
    }

    #[tokio::test]
    async fn test_row_group_bloom_filter_pruning_predicate_with_exists_value() {
        BloomFilterTest::new_data_index_bloom_encoding_stats()
            .with_expect_none_pruned()
            // generate pruning predicate `(String = "Hello")`
            .run(col(r#""String""#).eq(lit("Hello")))
            .await
    }

    #[tokio::test]
    async fn test_row_group_bloom_filter_pruning_predicate_with_exists_2_values() {
        BloomFilterTest::new_data_index_bloom_encoding_stats()
            .with_expect_none_pruned()
            // generate pruning predicate `(String = "Hello") OR (String = "the quick")`
            .run(
                col(r#""String""#)
                    .eq(lit("Hello"))
                    .or(col(r#""String""#).eq(lit("the quick"))),
            )
            .await
    }

    #[tokio::test]
    async fn test_row_group_bloom_filter_pruning_predicate_with_exists_3_values() {
        BloomFilterTest::new_data_index_bloom_encoding_stats()
            .with_expect_none_pruned()
            // generate pruning predicate `(String = "Hello") OR (String = "the quick") OR (String = "are you")`
            .run(
                col(r#""String""#)
                    .eq(lit("Hello"))
                    .or(col(r#""String""#).eq(lit("the quick")))
                    .or(col(r#""String""#).eq(lit("are you"))),
            )
            .await
    }

    #[tokio::test]
    async fn test_row_group_bloom_filter_pruning_predicate_with_exists_3_values_view() {
        BloomFilterTest::new_data_index_bloom_encoding_stats()
            .with_expect_none_pruned()
            // generate pruning predicate `(String = "Hello") OR (String = "the quick") OR (String = "are you")`
            .run(
                col(r#""String""#)
                    .eq(Expr::Literal(
                        ScalarValue::Utf8View(Some(String::from("Hello"))),
                        None,
                    ))
                    .or(col(r#""String""#).eq(Expr::Literal(
                        ScalarValue::Utf8View(Some(String::from("the quick"))),
                        None,
                    )))
                    .or(col(r#""String""#).eq(Expr::Literal(
                        ScalarValue::Utf8View(Some(String::from("are you"))),
                        None,
                    ))),
            )
            .await
    }

    #[tokio::test]
    async fn test_row_group_bloom_filter_pruning_predicate_with_or_not_eq() {
        BloomFilterTest::new_data_index_bloom_encoding_stats()
            .with_expect_none_pruned()
            // generate pruning predicate `(String = "foo") OR (String != "bar")`
            .run(
                col(r#""String""#)
                    .not_eq(lit("foo"))
                    .or(col(r#""String""#).not_eq(lit("bar"))),
            )
            .await
    }

    #[tokio::test]
    async fn test_row_group_bloom_filter_pruning_predicate_without_bloom_filter() {
        // generate pruning predicate on a column without a bloom filter
        BloomFilterTest::new_all_types()
            .with_expect_none_pruned()
            .run(col(r#""string_col""#).eq(lit("0")))
            .await
    }

    // What row groups are expected to be left after pruning
    #[derive(Debug)]
    enum ExpectedPruning {
        All,
        /// Only the specified row groups are expected to REMAIN (not what is pruned)
        Some(Vec<usize>),
        None,
    }

    impl ExpectedPruning {
        /// asserts that the pruned row group match this expectation
        fn assert(&self, row_groups: &RowGroupAccessPlanFilter) {
            let num_row_groups = row_groups.access_plan.len();
            assert!(num_row_groups > 0);
            let num_pruned = (0..num_row_groups)
                .filter_map(|i| {
                    if row_groups.access_plan.should_scan(i) {
                        None
                    } else {
                        Some(1)
                    }
                })
                .sum::<usize>();

            match self {
                Self::All => {
                    assert_eq!(
                        num_row_groups, num_pruned,
                        "Expected all row groups to be pruned, but got {row_groups:?}"
                    );
                }
                ExpectedPruning::None => {
                    assert_eq!(
                        num_pruned, 0,
                        "Expected no row groups to be pruned, but got {row_groups:?}"
                    );
                }
                ExpectedPruning::Some(expected) => {
                    let actual = row_groups.access_plan.row_group_indexes();
                    assert_eq!(expected, &actual, "Unexpected row groups pruned. Expected {expected:?}, got {actual:?}");
                }
            }
        }
    }

    fn assert_pruned(row_groups: RowGroupAccessPlanFilter, expected: ExpectedPruning) {
        expected.assert(&row_groups);
    }

    struct BloomFilterTest {
        file_name: String,
        schema: Schema,
        // which row groups are expected to be left after pruning
        post_pruning_row_groups: ExpectedPruning,
    }

    impl BloomFilterTest {
        /// Return a test for data_index_bloom_encoding_stats.parquet
        /// Note the values in the `String` column are:
        /// ```sql
        /// > select * from './parquet-testing/data/data_index_bloom_encoding_stats.parquet';
        /// +-----------+
        /// | String    |
        /// +-----------+
        /// | Hello     |
        /// | This is   |
        /// | a         |
        /// | test      |
        /// | How       |
        /// | are you   |
        /// | doing     |
        /// | today     |
        /// | the quick |
        /// | brown fox |
        /// | jumps     |
        /// | over      |
        /// | the lazy  |
        /// | dog       |
        /// +-----------+
        /// ```
        fn new_data_index_bloom_encoding_stats() -> Self {
            Self {
                file_name: String::from("data_index_bloom_encoding_stats.parquet"),
                schema: Schema::new(vec![Field::new("String", DataType::Utf8, false)]),
                post_pruning_row_groups: ExpectedPruning::None,
            }
        }

        // Return a test for alltypes_plain.parquet
        fn new_all_types() -> Self {
            Self {
                file_name: String::from("alltypes_plain.parquet"),
                schema: Schema::new(vec![Field::new(
                    "string_col",
                    DataType::Utf8,
                    false,
                )]),
                post_pruning_row_groups: ExpectedPruning::None,
            }
        }

        /// Expect all row groups to be pruned
        pub fn with_expect_all_pruned(mut self) -> Self {
            self.post_pruning_row_groups = ExpectedPruning::All;
            self
        }

        /// Expect all row groups not to be pruned
        pub fn with_expect_none_pruned(mut self) -> Self {
            self.post_pruning_row_groups = ExpectedPruning::None;
            self
        }

        /// Prune this file using the specified expression and check that the expected row groups are left
        async fn run(self, expr: Expr) {
            let Self {
                file_name,
                schema,
                post_pruning_row_groups,
            } = self;

            let testdata = datafusion_common::test_util::parquet_test_data();
            let path = format!("{testdata}/{file_name}");
            let data = bytes::Bytes::from(std::fs::read(path).unwrap());

            let expr = logical2physical(&expr, &schema);
            let pruning_predicate =
                PruningPredicate::try_new(expr, Arc::new(schema)).unwrap();

            let pruned_row_groups = test_row_group_bloom_filter_pruning_predicate(
                &file_name,
                data,
                &pruning_predicate,
            )
            .await
            .unwrap();

            post_pruning_row_groups.assert(&pruned_row_groups);
        }
    }

    /// Evaluates the pruning predicate on the specified row groups and returns the row groups that are left
    async fn test_row_group_bloom_filter_pruning_predicate(
        file_name: &str,
        data: bytes::Bytes,
        pruning_predicate: &PruningPredicate,
    ) -> Result<RowGroupAccessPlanFilter> {
        use object_store::{ObjectMeta, ObjectStore};

        let object_meta = ObjectMeta {
            location: object_store::path::Path::parse(file_name).expect("creating path"),
            last_modified: chrono::DateTime::from(std::time::SystemTime::now()),
            size: data.len() as u64,
            e_tag: None,
            version: None,
        };
        let in_memory = object_store::memory::InMemory::new();
        in_memory
            .put(&object_meta.location, data.into())
            .await
            .expect("put parquet file into in memory object store");

        let metrics = ExecutionPlanMetricsSet::new();
        let file_metrics =
            ParquetFileMetrics::new(0, object_meta.location.as_ref(), &metrics);
        let inner = ParquetObjectReader::new(Arc::new(in_memory), object_meta.location)
            .with_file_size(object_meta.size);

        let reader = ParquetFileReader {
            inner,
            file_metrics: file_metrics.clone(),
        };
        let mut builder = ParquetRecordBatchStreamBuilder::new(reader).await.unwrap();

        let access_plan = ParquetAccessPlan::new_all(builder.metadata().num_row_groups());
        let mut pruned_row_groups = RowGroupAccessPlanFilter::new(access_plan);
        pruned_row_groups
            .prune_by_bloom_filters(
                pruning_predicate.schema(),
                &mut builder,
                pruning_predicate,
                &file_metrics,
            )
            .await;

        Ok(pruned_row_groups)
    }
}
