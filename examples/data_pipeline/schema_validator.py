"""
AEON Enterprise Example: Schema Validator
===========================================
Industry: Data Engineering
Engines:  Dependent Types, Symbolic Execution, Shape Analysis

Demonstrates how AEON verifies:
- Schema definitions are consistent (no contradictions)
- Validation logic covers all field types
- Nested structures are correctly traversed

Run: aeon check examples/data_pipeline/schema_validator.py --deep-verify
"""

from typing import Dict, List, Optional, Any, Tuple


VALID_TYPES = ['string', 'int', 'float', 'bool', 'list', 'dict']


def validate_field(value: Any, field_type: str, required: bool) -> Tuple[bool, str]:
    """
    Validate a single field value against its declared type.

    Requires: field_type in ['string', 'int', 'float', 'bool', 'list', 'dict']
    Ensures:  result[0] == True or len(result[1]) > 0

    AEON's symbolic execution explores all 6 type branches plus the
    None/missing case and verifies each returns a valid (bool, str) pair.
    """
    if value is None:
        if required:
            return (False, "required field is missing")
        return (True, "")

    type_map = {
        'string': str,
        'int': int,
        'float': (int, float),
        'bool': bool,
        'list': list,
        'dict': dict,
    }

    expected = type_map.get(field_type)
    if expected is None:
        return (False, f"unknown type: {field_type}")

    if not isinstance(value, expected):
        return (False, f"expected {field_type}, got {type(value).__name__}")

    return (True, "")


def validate_record(
    record: dict,
    schema: Dict[str, dict],
) -> Dict[str, List[str]]:
    """
    Validate a record against a schema definition.

    Schema format: { "field_name": {"type": "string", "required": True}, ... }

    Requires: len(schema) > 0
    Ensures:  'errors' in result
    Ensures:  'valid' in result
    Ensures:  result['valid'] == (len(result['errors']) == 0)

    AEON's dependent types verify: the return type's 'valid' field
    is structurally dependent on the 'errors' list being empty.
    """
    errors = []

    for field_name, field_spec in schema.items():
        field_type = field_spec.get("type", "string")
        required = field_spec.get("required", False)
        value = record.get(field_name)

        is_valid, msg = validate_field(value, field_type, required)
        if not is_valid:
            errors.append(f"{field_name}: {msg}")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
    }


def validate_batch(
    records: List[dict],
    schema: Dict[str, dict],
) -> dict:
    """
    Validate a batch of records and return statistics.

    Requires: len(schema) > 0
    Ensures:  result['total'] == len(records)
    Ensures:  result['valid_count'] + result['invalid_count'] == result['total']
    Ensures:  result['valid_count'] >= 0
    Ensures:  result['invalid_count'] >= 0

    AEON's Hoare logic verifies the partition property:
    valid_count + invalid_count always equals total.
    """
    valid_count = 0
    invalid_count = 0
    all_errors = []

    for i, record in enumerate(records):
        result = validate_record(record, schema)
        if result["valid"]:
            valid_count += 1
        else:
            invalid_count += 1
            for err in result["errors"]:
                all_errors.append(f"record[{i}]: {err}")

    return {
        "total": len(records),
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "errors": all_errors,
        "pass_rate": round(valid_count / max(len(records), 1) * 100, 2),
    }


def infer_schema(records: List[dict]) -> Dict[str, dict]:
    """
    Infer a schema from a list of sample records.

    Requires: len(records) > 0
    Ensures:  len(result) > 0

    AEON's shape analysis verifies the nested dictionary
    structure is well-formed and all paths terminate.
    """
    schema: Dict[str, dict] = {}

    for record in records:
        for key, value in record.items():
            if key not in schema:
                if isinstance(value, str):
                    inferred_type = "string"
                elif isinstance(value, bool):
                    inferred_type = "bool"
                elif isinstance(value, int):
                    inferred_type = "int"
                elif isinstance(value, float):
                    inferred_type = "float"
                elif isinstance(value, list):
                    inferred_type = "list"
                elif isinstance(value, dict):
                    inferred_type = "dict"
                else:
                    inferred_type = "string"

                schema[key] = {
                    "type": inferred_type,
                    "required": True,
                }

    # Mark fields as optional if not present in all records
    for key in schema:
        present_count = sum(1 for r in records if key in r)
        if present_count < len(records):
            schema[key]["required"] = False

    return schema
