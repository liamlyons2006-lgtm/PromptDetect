"""
Scenario data validation tests.
Verifies that the ScenarioProvider meets all requirements from Requirement 6.
Feature: prompt-injection-detector
"""

from __future__ import annotations

import pytest

from app.samples.provider import ScenarioProvider

PROVIDER = ScenarioProvider()
REQUIRED_CATEGORIES = [
    "Corporate Data Exfiltration",
    "Customer Service Bot Hijacking",
    "AI Assistant Jailbreak",
    "Document Poisoning Attack",
    "Legitimate Business Use",
]


# ---------------------------------------------------------------------------
# Requirement 6.1 / 6.2 — Required categories present
# ---------------------------------------------------------------------------

def test_all_required_scenario_categories_present():
    scenarios = PROVIDER.get_all_scenarios()
    names = [s.name for s in scenarios]
    for required in REQUIRED_CATEGORIES:
        assert required in names, f"Missing required scenario: {required}"


# ---------------------------------------------------------------------------
# Requirement 6.5 — At least 3 prompts per category
# ---------------------------------------------------------------------------

def test_minimum_3_prompts_per_scenario():
    for scenario in PROVIDER.get_all_scenarios():
        assert len(scenario.prompts) >= 3, (
            f"Scenario '{scenario.name}' has only {len(scenario.prompts)} prompts"
        )


# ---------------------------------------------------------------------------
# Requirement 6.6 — Each scenario has a description
# ---------------------------------------------------------------------------

def test_each_scenario_has_description():
    for scenario in PROVIDER.get_all_scenarios():
        assert scenario.description and len(scenario.description) > 10, (
            f"Scenario '{scenario.name}' has no meaningful description"
        )


# ---------------------------------------------------------------------------
# Requirement 6.7 — Coverage of all threat types
# ---------------------------------------------------------------------------

def test_minimum_threat_type_coverage():
    all_prompts = PROVIDER.get_all_prompts()
    categories = [p.expected_category for p in all_prompts]
    assert categories.count("jailbreak") >= 3, "Need at least 3 jailbreak prompts"
    assert categories.count("indirect_injection") >= 3, "Need at least 3 indirect_injection prompts"
    assert categories.count("safe") >= 3, "Need at least 3 safe prompts"


# ---------------------------------------------------------------------------
# Requirement 6.10 — Each prompt has an explanation
# ---------------------------------------------------------------------------

def test_each_prompt_has_explanation():
    for scenario in PROVIDER.get_all_scenarios():
        for prompt in scenario.prompts:
            assert prompt.explanation and len(prompt.explanation) > 10, (
                f"Prompt '{prompt.id}' in '{scenario.name}' has no explanation"
            )


# ---------------------------------------------------------------------------
# Requirement 6.8 — get_demo_sequence returns one per scenario
# ---------------------------------------------------------------------------

def test_demo_sequence_one_per_scenario():
    scenarios = PROVIDER.get_all_scenarios()
    sequence = PROVIDER.get_demo_sequence()
    assert len(sequence) == len(scenarios), (
        f"Demo sequence has {len(sequence)} items, expected {len(scenarios)}"
    )


# ---------------------------------------------------------------------------
# Scenario IDs are unique
# ---------------------------------------------------------------------------

def test_scenario_ids_unique():
    scenarios = PROVIDER.get_all_scenarios()
    ids = [s.id for s in scenarios]
    assert len(ids) == len(set(ids)), "Scenario IDs are not unique"


# ---------------------------------------------------------------------------
# Prompt IDs are unique across all scenarios
# ---------------------------------------------------------------------------

def test_prompt_ids_globally_unique():
    all_prompts = PROVIDER.get_all_prompts()
    ids = [p.id for p in all_prompts]
    assert len(ids) == len(set(ids)), "Prompt IDs are not globally unique"


# ---------------------------------------------------------------------------
# get_scenario by ID works
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scenario", PROVIDER.get_all_scenarios())
def test_get_scenario_by_id(scenario):
    found = PROVIDER.get_scenario(scenario.id)
    assert found is not None
    assert found.id == scenario.id
    assert found.name == scenario.name


def test_get_scenario_unknown_id_returns_none():
    assert PROVIDER.get_scenario("non-existent-id") is None


# ---------------------------------------------------------------------------
# expected_category values are valid
# ---------------------------------------------------------------------------

def test_expected_category_values_valid():
    valid = {"safe", "jailbreak", "indirect_injection"}
    for scenario in PROVIDER.get_all_scenarios():
        for prompt in scenario.prompts:
            assert prompt.expected_category in valid, (
                f"Prompt '{prompt.id}' has invalid expected_category: {prompt.expected_category}"
            )
