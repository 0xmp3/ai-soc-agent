# Same flow, LangGraph

The hunt → gate → contain flow from the root of this repo, written against LangGraph.
It exists to answer one question with evidence instead of opinion: **what does an agent
framework actually buy a security agent, and what does it hide?**

It reuses this repo's allowlist — `GUARDRAILS.ALLOWED_TABLES` via
`validate_tables_and_fields` — rather than copying it, so the comparison is between two
control-flow designs over one set of guardrails, not two different products.

**It is not a second production path.** The Azure and model clients are behind two
protocols (`Planner`, `QueryClient`) and are stubbed here. What is real is the graph, the
durable gate, and the tests.

## Run it

```bash
py -3.12 -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt -r implementations/langgraph/requirements.txt
.venv/Scripts/python.exe -m pytest implementations/langgraph -q     # 8 tests, offline
.venv/Scripts/python.exe -m pytest tests -q                          # the repo's 39, still green
```

No Azure credentials, no API key, no network in either suite.

By hand, to watch the gate park:

```bash
.venv/Scripts/python.exe implementations/langgraph/agent.py start "odd sign-ins on WS-014?"
.venv/Scripts/python.exe implementations/langgraph/agent.py show
.venv/Scripts/python.exe implementations/langgraph/agent.py resume approve    # or deny
```

Each of those is a separate OS process. Only `hunt.db` carries state between them.

## What it adds

**A gate that survives a restart.** `interrupt()` suspends inside a node and the
checkpointer writes the whole state to SQLite. The process can exit; a different process
resumes at the same instruction. The hand-rolled flow keeps the pending containment
action in a Python variable, so a restart between "prompt" and "answer" loses it with no
trace. `test_pending_action_survives_a_new_process` is that claim, as a test.

**A refusal that returns instead of exiting.** See the first finding below.

## The comparison

| | Hand-rolled (`EXECUTOR.py`) | This port |
|---|---|---|
| Control flow | `hunt()` returns a function call; `_main.py` dispatches | `StateGraph`: plan → gate → contain |
| Pending action across a restart | lost (in memory) | survives (SQLite checkpointer) |
| Guardrail violation | `exit(1)` — the run dies | returned as a value; run completes, nothing contained |
| Approval location | prompt in `_main.py` | `interrupt()` inside the gate node |
| Offline tests | 39 | 8, including resume in a new graph instance |
| Code size | `EXECUTOR.py` 247 lines / 171 non-blank (includes Azure auth, MDE device lookup, action polling) | `agent.py` 205 lines / 144 non-blank (includes two protocol stubs and a CLI) |

The line counts are **not** like-for-like and should not be read as a saving: the
hand-rolled file carries real Azure plumbing that this port stubs out. The difference
worth measuring is capability, not length.

## What porting surfaced

Three things found by moving the same guardrails behind a graph. All verified on this
host, all reproducible with the commands in this file.

1. **`validate_tables_and_fields` exits the process.** Correct for a batch CLI — a human
   reads the message and fixes the query. Fatal inside a graph node, because the model
   never learns *why* and every refusal costs a whole run. `_validate()` wraps it and
   converts the exit into a returned reason.

2. **Two allowlisted tables are unusable.** `AlertInfo` and `AlertEvidence` carry an
   empty field set, and the validator rejects any field not in that set — so every query
   against them exits:

   ```
   AlertInfo       TimeGenerated   -> EXIT 1
   AlertEvidence   DeviceName      -> EXIT 1
   SigninLogs      TimeGenerated,IPAddress -> accepted
   ```

   The empty set reads as "fields unspecified", the validator implements it as "no field
   allowed". Either the sets need filling or the validator needs to treat empty as
   allow-all. Not changed here: that is a behaviour change to the production path.

3. **A refusal should finish the run, not park it.** First draft of the test expected the
   refusal to reach the gate and wait for a human; the graph correctly ran straight
   through to `END` with `result: "not executed — GUARDRAILS refused ..."`. Waiting for an
   approval on a query that was never run would be a prompt with nothing behind it.

## Limits, stated plainly

- The `Planner` and `QueryClient` adapters are stubs. Wiring them to
  `EXECUTOR.get_query_context`, `hunt()`, and `quarantine_virtual_machine()` is the work
  that would make this a second production path, and it is deliberately not done.
- No retry cap on the model loop. LangGraph will not stop a model that keeps re-proposing
  a refused table; that needs an attempt counter in `State` or `recursion_limit`.
- The checkpointer is SQLite in the module directory. Production wants a durable store
  and a retention policy — the same objection as keeping conversation history in a local
  file, and it is a real one.
