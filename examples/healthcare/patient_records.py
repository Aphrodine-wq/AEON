"""
AEON Enterprise Example: Patient Records (HIPAA Compliance)
============================================================
Industry: Healthcare
Engines:  Information Flow, Taint Analysis, Effect Algebra

Demonstrates how AEON enforces:
- Protected Health Information (PHI) never leaks to public endpoints
- Audit trail on every data access
- Role-based access control verified at compile time

Run: aeon check examples/healthcare/patient_records.py --deep-verify
"""

from typing import List, Optional


# Security labels (AEON tracks these through the program)
# PUBLIC < INTERNAL < PHI < RESTRICTED


class PatientRecord:
    """Patient health record — all fields are PHI-labeled."""
    def __init__(self, patient_id: str, name: str, ssn: str, diagnosis: str, medications: List[str]):
        """
        Requires: len(patient_id) > 0
        Requires: len(ssn) == 11
        """
        self.patient_id = patient_id   # PHI
        self.name = name               # PHI
        self.ssn = ssn                 # RESTRICTED
        self.diagnosis = diagnosis     # PHI
        self.medications = medications # PHI


def get_patient_summary_unsafe(record: PatientRecord) -> dict:
    """
    Return a patient summary for a public-facing dashboard.

    BUG: PHI data (name, diagnosis) flows to PUBLIC output.
    AEON's information flow analysis catches this:
      record.name is PHI, return value is PUBLIC.
      Lattice violation: PHI <= PUBLIC.

    BUG: SSN (RESTRICTED) also leaks — even worse.
    """
    return {
        "id": record.patient_id,
        "name": record.name,           # BUG: PHI -> PUBLIC
        "diagnosis": record.diagnosis, # BUG: PHI -> PUBLIC
        "ssn": record.ssn,            # BUG: RESTRICTED -> PUBLIC
    }


def get_patient_summary_safe(record: PatientRecord) -> dict:
    """
    Return a de-identified patient summary safe for public use.

    Ensures: no PHI or RESTRICTED data in result
    Ensures: result['id'] is a hash, not the real patient_id

    AEON verifies: all returned fields are PUBLIC-labeled.
    """
    anonymized_id = hash(record.patient_id) % 1000000
    return {
        "id": anonymized_id,
        "record_exists": True,
        "medication_count": len(record.medications),
    }


def lookup_patient(
    records: List[PatientRecord],
    patient_id: str,
    requesting_role: str,
) -> Optional[dict]:
    """
    Look up a patient record with role-based access control.

    Requires: len(patient_id) > 0
    Requires: requesting_role in ['doctor', 'nurse', 'admin', 'billing']
    Ensures:  requesting_role == 'billing' implies 'ssn' not in result
    Ensures:  requesting_role == 'nurse' implies 'ssn' not in result

    AEON's information flow verifies each role only sees
    data at or below their clearance level.
    """
    for record in records:
        if record.patient_id == patient_id:
            if requesting_role == "doctor":
                return {
                    "patient_id": record.patient_id,
                    "name": record.name,
                    "diagnosis": record.diagnosis,
                    "medications": record.medications,
                }
            elif requesting_role == "nurse":
                return {
                    "patient_id": record.patient_id,
                    "name": record.name,
                    "medications": record.medications,
                }
            elif requesting_role == "billing":
                return {
                    "patient_id": record.patient_id,
                    "name": record.name,
                }
            else:
                return None
    return None


def generate_audit_log(
    action: str, patient_id: str, accessor_id: str, role: str
) -> dict:
    """
    Generate an immutable audit log entry for HIPAA compliance.

    Requires: len(action) > 0
    Requires: len(patient_id) > 0
    Requires: len(accessor_id) > 0
    Ensures:  all keys in ['action', 'patient_id', 'accessor_id', 'role', 'timestamp'] are present

    AEON's effect algebra verifies that every patient data access
    is paired with an audit log write (Database.Write effect).
    """
    import time
    return {
        "action": action,
        "patient_id": patient_id,
        "accessor_id": accessor_id,
        "role": role,
        "timestamp": int(time.time()),
    }
