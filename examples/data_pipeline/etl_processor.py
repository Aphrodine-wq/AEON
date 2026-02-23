"""
AEON Enterprise Example: ETL Processor
========================================
Industry: Data Engineering
Engines:  Termination Analysis, Abstract Interpretation, Effect Algebra

Demonstrates how AEON verifies:
- All ETL pipelines terminate (no infinite loops)
- Aggregation accumulators don't overflow
- Side effects (DB writes) are tracked and ordered

Run: aeon check examples/data_pipeline/etl_processor.py --deep-verify
"""

from typing import List, Dict, Callable, Optional, Any


def extract_records(
    source_data: List[dict], required_fields: List[str]
) -> List[dict]:
    """
    Extract and filter records that have all required fields.

    Requires: len(required_fields) > 0
    Ensures:  len(result) <= len(source_data)
    Ensures:  all(all(f in r for f in required_fields) for r in result)

    AEON's termination analysis confirms: single-pass over
    a finite list always terminates. The loop variable i
    strictly increases toward len(source_data).
    """
    valid_records = []
    for record in source_data:
        if all(field in record for field in required_fields):
            valid_records.append(record)
    return valid_records


def transform_records(
    records: List[dict],
    field_mapping: Dict[str, str],
) -> List[dict]:
    """
    Transform records by renaming fields according to a mapping.

    Requires: len(records) >= 0
    Requires: len(field_mapping) > 0
    Ensures:  len(result) == len(records)

    AEON's termination analysis: nested loops are bounded
    by len(records) * len(field_mapping), both finite.
    """
    transformed = []
    for record in records:
        new_record = {}
        for old_key, new_key in field_mapping.items():
            if old_key in record:
                new_record[new_key] = record[old_key]
        transformed.append(new_record)
    return transformed


def aggregate_sum(records: List[dict], field: str) -> int:
    """
    Sum a numeric field across all records.

    Requires: len(field) > 0
    Ensures:  result >= 0 if all values >= 0

    AEON's abstract interpretation tracks the accumulator range.
    With N records each having values in [-M, M], the sum is
    bounded by [-N*M, N*M]. Flags potential overflow for large N.
    """
    total = 0
    for record in records:
        value = record.get(field, 0)
        if isinstance(value, (int, float)):
            total += int(value)
    return total


def aggregate_group_by(
    records: List[dict], group_field: str, sum_field: str
) -> Dict[str, int]:
    """
    Group records by a field and sum another field per group.

    Requires: len(group_field) > 0
    Requires: len(sum_field) > 0
    Ensures:  all(v >= 0 for v in result.values()) if all values >= 0

    AEON's effect algebra tracks that this is a pure computation
    with no side effects — safe to parallelize or memoize.
    """
    groups: Dict[str, int] = {}
    for record in records:
        key = str(record.get(group_field, "unknown"))
        value = int(record.get(sum_field, 0))

        if key in groups:
            groups[key] += value
        else:
            groups[key] = value

    return groups


def load_batch(
    records: List[dict], batch_size: int
) -> List[List[dict]]:
    """
    Split records into batches for loading.

    Requires: batch_size > 0
    Ensures:  sum(len(batch) for batch in result) == len(records)
    Ensures:  all(len(batch) <= batch_size for batch in result)

    AEON's Hoare logic verifies the partition property:
    every record appears in exactly one batch, and no batch
    exceeds batch_size.

    AEON catches: division by zero if batch_size == 0
    (precondition prevents this).
    """
    batches = []
    for i in range(0, len(records), batch_size):
        batch = records[i:i + batch_size]
        batches.append(batch)
    return batches


def run_pipeline(
    source_data: List[dict],
    required_fields: List[str],
    field_mapping: Dict[str, str],
    batch_size: int,
) -> dict:
    """
    Run the full ETL pipeline: extract -> transform -> batch.

    Requires: batch_size > 0
    Requires: len(required_fields) > 0
    Requires: len(field_mapping) > 0
    Ensures:  result['status'] == 'completed'
    Ensures:  result['records_processed'] <= len(source_data)

    AEON's effect algebra verifies the pipeline stages
    compose correctly: Extract (pure) -> Transform (pure) -> Load (Database.Write).
    """
    # Extract
    valid = extract_records(source_data, required_fields)

    # Transform
    transformed = transform_records(valid, field_mapping)

    # Batch for loading
    batches = load_batch(transformed, batch_size)

    return {
        'status': 'completed',
        'records_processed': len(transformed),
        'batches_created': len(batches),
        'records_filtered': len(source_data) - len(valid),
    }
