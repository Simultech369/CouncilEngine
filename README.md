# CouncilEngine

Offline deterministic verification helper, task router, AST/policy auditor, human-approval promotion gate, and RLVR reward harness for local control planes.

> [!NOTE]
> **Role in the Stack**
> - **Dizzy ([`Dizzy-the-Polymath`](https://github.com/Simultech369/Dizzy-the-Polymath))** is the local router and control plane (routing, bounded memory rules, tools, receipts, Operator Inbox, and user-facing channels).
> - **CouncilEngine** is the **offline verification helper** (checks code/policy, routes specialist verification tasks, reports promotion blockers, and enforces human-approval promotion gates) -- **not** a second consumer chat brain.
> - **Pharmacy / PBM ([`Pharmacy-Fiduciary-Commons`](https://github.com/Simultech369/Pharmacy-Fiduciary-Commons))** is one optional vertical domain module (`pbm_*.py`), not the whole engine.

---

## 1. Core Surfaces & Egress Boundaries

| Workflow Layer | Egress & Execution Posture | Key Modules |
| :--- | :--- | :--- |
| **Verification Task Router** | **Deterministic Local Routing**: Accepts verification jobs, tracks state (`queued -> running -> waiting_for_approval -> approved \| rejected`), and lists exact promotion blockers. | `task_router.py`, `council_api_server.py` |
| **Human-Approval Gate (HITL)** | **Dual-Control Sign-Off**: Issues signed `resume_token` checkpoints, records approve/reject decisions in a hash-chained audit log, and shares canonical approval states with Dizzy (`waiting_for_approval`, `approved`, `rejected`, `resumed`, `cancelled`). | `human_approval.py`, `council_api_server.py` |
| **Static Rehearsal & AST Audit** | **Strictly Offline / Zero Egress**: Dead-code/wrapper AST scanner and static patch validation without repository mutation. | `anti_wrapper_audit.py`, `sovereign_swebench_batch_runner.py` |
| **Consensus & Formal Checks** | **Deterministic Local Math**: Merkle state proofs, CWE vulnerability AST checks, and typed receipt envelopes. | `council_contracts.py`, `bounty_vulnerability_engine.py`, `distributed_merkle_state_sync.py` |
| **Model Gateway Guardrails** | **Bounded Adapter Surface**: Local/mock adapters by default, PII leak guard, spend ledger, and bounded schema-validation retries with receipts. | `model_gateway.py`, `windows_spend_ledger.py` |

---

## 2. Quick Start (Mac/Linux and Windows)

### Prerequisites
- Python 3.10+ (tested on Python 3.12)
- `pip install pytest pytest-asyncio anyio pydantic pynacl requests z3-solver`

### Mac / Linux (Bash)

```bash
git clone https://github.com/Simultech369/CouncilEngine.git
cd CouncilEngine

# Run the offline verification test suite (zero external network calls)
python3 -m pytest -q

# Run the anti-wrapper AST regression gate
python3 -B anti_wrapper_audit.py --target-dir . --baseline-file ANTI_WRAPPER_BASELINE.json --fail-on-regression
```

### Windows (PowerShell)

```powershell
git clone https://github.com/Simultech369/CouncilEngine.git
Set-Location -LiteralPath ".\CouncilEngine"

python -m pytest -q
python -B anti_wrapper_audit.py --target-dir . --baseline-file ANTI_WRAPPER_BASELINE.json --fail-on-regression
```

---

## 3. Shared Approval State Contract with Dizzy

Both Dizzy (`lib/hitl_approval_gateway.mjs`) and CouncilEngine (`human_approval.py`) enforce the same explicit workflow states for promotion and authority upgrades:

```text
running -> waiting_for_approval -> approved | rejected -> resumed | cancelled
```

- Promotion or authority upgrades never auto-approve silently.
- Every approval or rejection binds to the target payload SHA-256, issues/verifies a cryptographic `resume_token`, and appends an entry to a hash-chained audit log.

---

## 4. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
