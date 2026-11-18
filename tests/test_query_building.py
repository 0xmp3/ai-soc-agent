import json
import types

import pytest

import EXECUTOR
import UTILITIES


class FakeResponse:
    tables = [types.SimpleNamespace(columns=["TimeGenerated"], rows=[["2026-02-03T22:01:11Z"]])]


class FakeClient:
    """Stands in for azure.monitor.query.LogsQueryClient and records the query text."""

    def __init__(self):
        self.query = None

    def query_workspace(self, workspace_id, query, timespan):
        self.query = query
        return FakeResponse()


def build(table, fields, *, device_name="", caller="", user_principal_name="", **kwargs):
    client = FakeClient()
    EXECUTOR.query_log_analytics(
        log_analytics_client=client,
        workspace_id="workspace",
        timerange_hours=24,
        table_name=table,
        device_name=device_name,
        fields=fields,
        caller=caller,
        user_principal_name=user_principal_name,
        **kwargs,
    )
    return client.query


def test_device_table_filters_on_startswith():
    query = build("DeviceLogonEvents", "TimeGenerated, DeviceName", device_name="web-01")
    assert query.splitlines()[1] == '| where DeviceName startswith "web-01"'


def test_signin_table_filters_on_upn():
    query = build("SigninLogs", "TimeGenerated, UserPrincipalName", user_principal_name="a@b.com")
    assert 'UserPrincipalName startswith "a@b.com"' in query


def test_network_analytics_filters_on_flow_type():
    query = build("AzureNetworkAnalytics_CL", "TimeGenerated, FlowType_s")
    assert 'FlowType_s == "MaliciousFlow"' in query


def test_azure_activity_without_exclusions():
    query = build("AzureActivity", "TimeGenerated, Caller")
    assert "!in (" not in query
    assert "isnotempty(Caller)" in query


def test_azure_activity_renders_exclusion_list_before_the_caller_filter():
    guids = ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"]
    query = build("AzureActivity", "TimeGenerated, Caller", excluded_callers=guids)
    expected = '| where Caller !in ("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")'
    assert expected in query
    assert query.index("!in (") < query.index("isnotempty(Caller)")


def test_exclusion_list_is_not_rendered_when_empty():
    for empty in (None, []):
        query = build("AzureActivity", "TimeGenerated, Caller", excluded_callers=empty)
        assert "!in (" not in query


@pytest.mark.parametrize(
    "payload",
    [
        'x" | where 1==1 | project * //',
        "x\n| where 1==1",
        "x; drop",
        "x\\",
    ],
)
def test_model_supplied_values_cannot_splice_the_query(payload):
    context = UTILITIES.sanitize_query_context({"fields": ["TimeGenerated"], "device_name": payload})
    query = build("DeviceLogonEvents", context["fields"], device_name=context["device_name"])

    filter_lines = [line for line in query.splitlines() if "where DeviceName" in line]
    assert len(filter_lines) == 1, query
    assert payload not in filter_lines[0], query


def test_query_returns_records_and_count():
    result = EXECUTOR.query_log_analytics(
        log_analytics_client=FakeClient(),
        workspace_id="workspace",
        timerange_hours=24,
        table_name="DeviceLogonEvents",
        device_name="web-01",
        fields="TimeGenerated",
        caller="",
        user_principal_name="",
    )
    assert result["count"] == 1
    assert "2026-02-03T22:01:11Z" in result["records"]


def test_hunt_parses_json_findings():
    findings = {"findings": [{"title": "Password spray", "confidence": "High"}]}

    class Completions:
        def create(self, **kwargs):
            message = types.SimpleNamespace(content=json.dumps(findings))
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=message)])

    client = types.SimpleNamespace(chat=types.SimpleNamespace(completions=Completions()))
    assert EXECUTOR.hunt(client, {"role": "system"}, {"role": "user"}, "gpt-5-mini") == findings
