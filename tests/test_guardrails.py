import pytest

import GUARDRAILS


def test_known_table_and_fields_are_accepted():
    GUARDRAILS.validate_tables_and_fields("SigninLogs", "TimeGenerated, IPAddress")


def test_unknown_table_exits():
    with pytest.raises(SystemExit) as exc:
        GUARDRAILS.validate_tables_and_fields("NotARealTable", "TimeGenerated")
    assert exc.value.code == 1


def test_field_not_exposed_by_that_table_exits():
    # Password exists in nobody's allowlist, but the point is the per-table check
    with pytest.raises(SystemExit) as exc:
        GUARDRAILS.validate_tables_and_fields("SigninLogs", "TimeGenerated, Password")
    assert exc.value.code == 1


def test_field_valid_for_one_table_is_rejected_for_another():
    # SHA256 is exposed on DeviceFileEvents only
    GUARDRAILS.validate_tables_and_fields("DeviceFileEvents", "TimeGenerated, SHA256")
    with pytest.raises(SystemExit):
        GUARDRAILS.validate_tables_and_fields("DeviceLogonEvents", "TimeGenerated, SHA256")


def test_known_model_is_accepted():
    GUARDRAILS.validate_model("gpt-5-mini")


@pytest.mark.parametrize("model", ["gpt-3.5-turbo", "gpt-4o", ""])
def test_unlisted_model_exits(model):
    with pytest.raises(SystemExit) as exc:
        GUARDRAILS.validate_model(model)
    assert exc.value.code == 1


def test_every_allowed_model_carries_the_data_the_cost_guardrail_needs():
    for name, info in GUARDRAILS.ALLOWED_MODELS.items():
        for key in ("max_input_tokens", "max_output_tokens",
                    "cost_per_million_input", "cost_per_million_output", "tier"):
            assert key in info, f"{name} is missing {key}"
