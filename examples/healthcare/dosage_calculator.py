"""
AEON Enterprise Example: Dosage Calculator
============================================
Industry: Healthcare
Engines:  Contracts (Hoare Logic), Abstract Interpretation, Symbolic Execution

Demonstrates how AEON verifies:
- Dosage always stays within safe therapeutic ranges
- Weight-based calculations never produce dangerous values
- Age-adjusted dosages are always safe

Run: aeon check examples/healthcare/dosage_calculator.py --deep-verify
"""

from typing import Tuple


def calculate_dosage_mg(
    weight_kg: float, dose_per_kg: float, max_dose_mg: float
) -> float:
    """
    Calculate medication dosage based on patient weight.

    Requires: weight_kg > 0.0
    Requires: weight_kg <= 500.0
    Requires: dose_per_kg > 0.0
    Requires: dose_per_kg <= 100.0
    Requires: max_dose_mg > 0.0
    Ensures:  result > 0.0
    Ensures:  result <= max_dose_mg

    AEON's Hoare logic verifies the min() clamp guarantees
    the postcondition result <= max_dose_mg on every path.
    """
    raw_dose = weight_kg * dose_per_kg
    return min(raw_dose, max_dose_mg)


def pediatric_dosage(
    age_years: int, adult_dose_mg: float
) -> float:
    """
    Calculate pediatric dosage using Clark's rule.

    Requires: age_years >= 0
    Requires: age_years <= 17
    Requires: adult_dose_mg > 0.0
    Ensures:  result > 0.0
    Ensures:  result < adult_dose_mg

    AEON catches: if age_years == 0, weight would be 0,
    making the fraction 0/150 = 0, violating result > 0.0
    Fix: use age_years + 1 or minimum weight floor.
    """
    estimated_weight_lbs = (age_years + 1) * 5 + 10  # rough estimate
    fraction = estimated_weight_lbs / 150.0
    return adult_dose_mg * fraction


def split_into_doses(
    total_daily_mg: float, doses_per_day: int
) -> Tuple[float, int]:
    """
    Split total daily dosage into individual doses.

    Requires: total_daily_mg > 0.0
    Requires: doses_per_day > 0
    Requires: doses_per_day <= 6
    Ensures:  result[0] > 0.0
    Ensures:  result[0] * result[1] >= total_daily_mg * 0.99

    AEON catches: division by zero if doses_per_day == 0.
    AEON's abstract interpretation verifies per_dose > 0
    given the preconditions.
    """
    per_dose = total_daily_mg / doses_per_day
    return (round(per_dose, 2), doses_per_day)


def check_drug_interaction_risk(
    drug_a_dose_mg: float,
    drug_b_dose_mg: float,
    interaction_factor: float,
) -> str:
    """
    Assess risk level of combining two drugs.

    Requires: drug_a_dose_mg >= 0.0
    Requires: drug_b_dose_mg >= 0.0
    Requires: interaction_factor >= 0.0
    Requires: interaction_factor <= 10.0
    Ensures:  result in ['safe', 'caution', 'dangerous']

    AEON's symbolic execution explores all branches and confirms
    every path returns one of the three valid risk levels.
    """
    combined_effect = (drug_a_dose_mg + drug_b_dose_mg) * interaction_factor

    if combined_effect < 100:
        return "safe"
    elif combined_effect < 500:
        return "caution"
    else:
        return "dangerous"
