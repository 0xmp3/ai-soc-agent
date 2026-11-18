import pytest

import GUARDRAILS
import MODEL_MANAGEMENT


def nano():
    return GUARDRAILS.ALLOWED_MODELS["gpt-4.1-nano"]


def test_one_million_of_each_is_input_plus_output_price():
    # $0.10/M input + $0.40/M output
    assert MODEL_MANAGEMENT.estimate_cost(1_000_000, 1_000_000, nano()) == pytest.approx(0.50)


def test_cost_is_zero_for_no_tokens():
    assert MODEL_MANAGEMENT.estimate_cost(0, 0, nano()) == 0


def test_cost_scales_linearly():
    one = MODEL_MANAGEMENT.estimate_cost(10_000, 500, nano())
    two = MODEL_MANAGEMENT.estimate_cost(20_000, 1_000, nano())
    assert two == pytest.approx(one * 2)


def test_money_formatting_switches_precision_at_one_cent():
    assert MODEL_MANAGEMENT.money(0.0042) == "$0.004200"
    assert MODEL_MANAGEMENT.money(0.17) == "$0.17"


def test_payload_over_the_context_limit_is_reported(capsys):
    MODEL_MANAGEMENT.assess_limits("gpt-4.1-nano", 2_000_000, tier="5")
    out = capsys.readouterr().out
    assert "ERROR" in out and "exceeds the input limit" in out


def test_payload_over_the_rate_tier_is_warned_about(capsys):
    # gpt-4.1-nano tier 2 allows 2,000,000 TPM, tier 1 allows 200,000
    MODEL_MANAGEMENT.assess_limits("gpt-4.1-nano", 500_000, tier="1")
    assert "exceeds the TPM rate limit" in capsys.readouterr().out


def test_payload_within_limits_is_safe(capsys):
    MODEL_MANAGEMENT.assess_limits("gpt-4.1-nano", 10_000, tier="5")
    out = capsys.readouterr().out
    assert "Safe" in out and "ERROR" not in out


def test_non_interactive_selection_returns_the_model(capsys):
    picked = MODEL_MANAGEMENT.choose_model("gpt-4.1", 10_000, tier="4", interactive=False)
    assert picked == "gpt-4.1"


def test_unknown_model_falls_back_to_the_default(capsys):
    picked = MODEL_MANAGEMENT.choose_model("gpt-3.5-turbo", 10_000, tier="4", interactive=False)
    assert picked == MODEL_MANAGEMENT.DEFAULT_MODEL


def test_counting_uses_the_tokenizer(capsys):
    messages = [{"role": "user", "content": "one two three four five"}]
    assert MODEL_MANAGEMENT.count_tokens(messages, "gpt-4.1-nano") > 0
