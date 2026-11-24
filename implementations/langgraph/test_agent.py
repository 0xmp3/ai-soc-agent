"""Offline tests for the LangGraph implementation.

No Azure credentials, no model, no network. The two seams (Planner, QueryClient) are
scripted, which is the point: the graph's behaviour is testable without the cloud, and
the containment decision is exercised both ways.

    .venv/Scripts/python.exe -m pytest implementations/langgraph -q
"""

from __future__ import annotations

# Windows: the repo root has GUARDRAILS.py and its tests import it bare, so pytest's
# rootdir insertion is enough — but keep this explicit so a run from elsewhere works.
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from implementations.langgraph.agent import Plan, build, open_graph  # noqa: E402


class Fakes:
    def __init__(self, table="SigninLogs", fields=("TimeGenerated", "IPAddress"), rows=None):
        self.plan_value = Plan(table, list(fields), 60, "WS-014")
        self.rows = rows if rows is not None else [{"TimeGenerated": "t", "IPAddress": "203.0.113.9"}]
        self.queries = 0
        self.contained: list[str] = []

    # Planner
    def plan(self, question):
        return self.plan_value

    def assess(self, question, rows):
        return f"{len(rows)} rows"

    # QueryClient
    def run_query(self, plan):
        self.queries += 1
        return self.rows

    def contain(self, device):
        self.contained.append(device)
        return f"{device} isolated"


def _graph(tmp_path, fakes, db_name="hunt.db"):
    return open_graph(tmp_path / db_name, fakes, fakes)


CFG = {"configurable": {"thread_id": "t-1"}}


def test_allowed_query_returns_rows_and_arms_a_gated_action(tmp_path):
    f = Fakes()
    g, conn = _graph(tmp_path, f)
    try:
        g.invoke({"question": "odd sign-ins?"}, CFG)
        snap = g.get_state(CFG)
        assert snap.next == ("gate",), "must stop at the gate, not run containment"
        assert snap.values["rows"] == f.rows
        assert snap.values["action"] == {"op": "contain", "device": "WS-014"}
        assert snap.interrupts, "an approval prompt must be pending"
        assert f.contained == [], "nothing may be contained before approval"
    finally:
        conn.close()


def test_disallowed_table_is_refused_without_raising(tmp_path):
    """The whole point of wrapping GUARDRAILS: exit(1) would kill the run."""
    f = Fakes(table="NotARealTable")
    g, conn = _graph(tmp_path, f)
    try:
        g.invoke({"question": "anything?"}, CFG)
        snap = g.get_state(CFG)
        assert snap.values["refused"].startswith("GUARDRAILS refused")
        assert snap.next == (), "a refusal finishes the run; nothing is left parked"
        assert snap.interrupts == (), "a refusal must never ask for approval"
        assert "not executed" in snap.values["result"]
        assert f.queries == 0
        assert f.contained == []
    finally:
        conn.close()


def test_disallowed_field_is_refused(tmp_path):
    f = Fakes(fields=("TimeGenerated", "SecretField"))
    g, conn = _graph(tmp_path, f)
    try:
        g.invoke({"question": "anything?"}, CFG)
        assert g.get_state(CFG).values["refused"].startswith("GUARDRAILS refused")
        assert f.queries == 0
    finally:
        conn.close()


def test_refused_run_never_contains(tmp_path):
    f = Fakes(table="NotARealTable")
    g, conn = _graph(tmp_path, f)
    try:
        g.invoke({"question": "anything?"}, CFG)
        assert "not executed" in g.get_state(CFG).values["result"]
        assert f.contained == []
    finally:
        conn.close()


def test_approve_contains(tmp_path):
    from langgraph.types import Command

    f = Fakes()
    g, conn = _graph(tmp_path, f)
    try:
        g.invoke({"question": "odd sign-ins?"}, CFG)
        g.invoke(Command(resume="approve"), CFG)
        assert f.contained == ["WS-014"]
        assert g.get_state(CFG).next == ()
    finally:
        conn.close()


def test_deny_does_not_contain(tmp_path):
    from langgraph.types import Command

    f = Fakes()
    g, conn = _graph(tmp_path, f)
    try:
        g.invoke({"question": "odd sign-ins?"}, CFG)
        g.invoke(Command(resume="deny"), CFG)
        assert f.contained == []
        assert "not executed" in g.get_state(CFG).values["result"]
    finally:
        conn.close()


def test_pending_action_survives_a_new_process(tmp_path):
    """Durability is the whole case for LangGraph, so it gets its own test.

    The first connection is closed before the resume, which is as close as a test can
    get to the process dying while a human decides.
    """
    from langgraph.types import Command

    f = Fakes()
    g, conn = _graph(tmp_path, f)
    g.invoke({"question": "odd sign-ins?"}, CFG)
    pending = g.get_state(CFG).interrupts
    conn.close()

    assert pending, "the prompt must be on disk"

    g2, conn2 = _graph(tmp_path, f)          # new connection, new compiled graph
    try:
        snap = g2.get_state(CFG)
        assert snap.next == ("gate",), "the parked node survives the restart"
        assert snap.interrupts[0].value == {"op": "contain", "device": "WS-014"}

        g2.invoke(Command(resume="approve"), CFG)
        assert f.contained == ["WS-014"], "resuming in a new graph must still contain"
    finally:
        conn2.close()


def test_two_threads_do_not_share_state(tmp_path):
    f = Fakes()
    g, conn = _graph(tmp_path, f)
    try:
        g.invoke({"question": "first"}, {"configurable": {"thread_id": "a"}})
        g.invoke({"question": "second"}, {"configurable": {"thread_id": "b"}})
        assert g.get_state({"configurable": {"thread_id": "a"}}).values["question"] == "first"
        assert g.get_state({"configurable": {"thread_id": "b"}}).values["question"] == "second"
    finally:
        conn.close()
