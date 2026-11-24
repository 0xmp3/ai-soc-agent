"""A LangGraph implementation of the same hunt -> gate -> contain flow.

Deliberately not a rewrite of the agent: same allowlist (imported from GUARDRAILS, not
copied), same two actions (query, contain), same question. What it adds is the two
things the hand-rolled loop in EXECUTOR.py cannot do:

  * **Durable state.** `interrupt()` plus a checkpointer means a run can stop, the
    process can die, and a new process can answer the containment prompt tomorrow.
    EXECUTOR.py holds the pending action in memory, so a restart loses it silently.

  * **A refusal the caller can act on.** `GUARDRAILS.validate_tables_and_fields` calls
    `exit(1)`: correct for a batch CLI, fatal inside a graph node, because it kills the
    run instead of letting the model correct the query. `_validate` below wraps it and
    returns a reason instead.

Run it:

    python implementations/langgraph/agent.py start "odd sign-ins on WS-014?"
    python implementations/langgraph/agent.py show
    python implementations/langgraph/agent.py resume approve

Tests are offline and need no Azure credentials, no model and no network:

    .venv/Scripts/python.exe -m pytest implementations/langgraph -q
"""

from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol, TypedDict

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from GUARDRAILS import validate_tables_and_fields  # noqa: E402  (repo root on path)
from langgraph.checkpoint.sqlite import SqliteSaver  # noqa: E402
from langgraph.graph import END, START, StateGraph  # noqa: E402
from langgraph.types import Command, interrupt  # noqa: E402

THREAD = "hunt-001"


# --- the seams the graph needs, so tests can run with no cloud -------------------


@dataclass(frozen=True)
class Plan:
    table: str
    fields: list[str]
    lookback_minutes: int
    device: str


class Planner(Protocol):
    """Whatever turns a question into a query, and rows into an assessment.

    The production adapter calls the model (EXECUTOR.get_query_context + hunt); the
    test adapter is scripted. Keeping this a Protocol is what makes the graph testable
    offline, which is the property the original loop lacks.
    """

    def plan(self, question: str) -> Plan: ...

    def assess(self, question: str, rows: list[dict]) -> str: ...


class QueryClient(Protocol):
    def run_query(self, plan: Plan) -> list[dict]: ...

    def contain(self, device: str) -> str: ...


# --- guardrail reuse -----------------------------------------------------------


def _validate(table: str, fields: list[str]) -> tuple[bool, str]:
    """Reuse the repo's guardrail, converting its exit into a value.

    A false refusal costs one retry; a false acceptance costs the premise. Both are
    cheaper than a dead graph, which is what exit(1) produces here.
    """
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            validate_tables_and_fields(table, ",".join(fields))
    except SystemExit:
        return False, f"GUARDRAILS refused table={table!r} fields={fields!r}"
    return True, ""


# --- graph ---------------------------------------------------------------------


class State(TypedDict, total=False):
    question: str
    plan: dict
    rows: list[dict]
    assessment: str
    action: dict
    decision: str
    result: str
    refused: str


def _make_nodes(planner: Planner, client: QueryClient):
    def plan_and_query(state: State) -> dict:
        p = planner.plan(state["question"])
        ok, why = _validate(p.table, p.fields)
        if not ok:
            # Stop here rather than containing anything on the strength of a refusal.
            return {"refused": why, "assessment": why, "rows": []}
        rows = client.run_query(p)
        return {
            "plan": asdict(p),
            "rows": rows,
            "assessment": planner.assess(state["question"], rows),
            "action": {"op": "contain", "device": p.device},
        }

    def gate(state: State) -> dict:
        if state.get("refused"):
            return {}
        answer = interrupt(state["action"])  # execution suspends inside this call
        return {"decision": str(answer)}

    def contain(state: State) -> dict:
        if state.get("refused"):
            return {"result": f"not executed — {state['refused']}"}
        if state.get("decision", "").lower() != "approve":
            return {"result": f"not executed — decision was {state.get('decision')!r}"}
        return {"result": client.contain(state["action"]["device"])}

    return plan_and_query, gate, contain


def build(planner: Planner, client: QueryClient, checkpointer: Any):
    plan_and_query, gate, contain = _make_nodes(planner, client)
    g = StateGraph(State)
    g.add_node("plan_and_query", plan_and_query)
    g.add_node("gate", gate)
    g.add_node("contain", contain)
    g.add_edge(START, "plan_and_query")
    g.add_edge("plan_and_query", "gate")
    g.add_edge("gate", "contain")
    g.add_edge("contain", END)
    return g.compile(checkpointer=checkpointer)


def open_graph(db: Path, planner: Planner, client: QueryClient):
    """A compiled graph over an on-disk checkpoint file. Caller closes the connection."""
    conn = sqlite3.connect(db, check_same_thread=False)
    return build(planner, client, SqliteSaver(conn)), conn


# --- CLI ----------------------------------------------------------------------


class _StubPlanner:
    """Placeholder for the model adapter; enough to exercise the graph by hand."""

    def plan(self, question: str) -> Plan:
        return Plan("SigninLogs", ["TimeGenerated", "UserPrincipalName", "IPAddress"], 1440, "WS-014")

    def assess(self, question: str, rows: list[dict]) -> str:
        return f"{len(rows)} row(s) returned; model adapter not wired in this stub."


class _StubClient:
    def run_query(self, plan: Plan) -> list[dict]:
        return [{"TimeGenerated": "2026-11-25T04:12:00Z", "UserPrincipalName": "a@example.com",
                 "IPAddress": "203.0.113.9"}]

    def contain(self, device: str) -> str:
        return f"{device} quarantine requested (stub; no API call made)"


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "show"
    db = ROOT / "implementations" / "langgraph" / "hunt.db"
    cfg = {"configurable": {"thread_id": THREAD}}
    graph, conn = open_graph(db, _StubPlanner(), _StubClient())
    try:
        if cmd == "start":
            q = argv[2] if len(argv) > 2 else "odd sign-ins on WS-014?"
            graph.invoke({"question": q}, cfg)
        elif cmd == "resume":
            graph.invoke(Command(resume=argv[2] if len(argv) > 2 else "approve"), cfg)

        snap = graph.get_state(cfg)
        print(f"thread {THREAD} · next {snap.next or '(finished)'}")
        print(json.dumps({k: v for k, v in snap.values.items()}, indent=2, default=str))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
