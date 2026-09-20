# CouncilEngine

Deterministic multi-agent governance, offline consensus verification, AST integrity auditing, and reinforcement learning verification (RLVR) reward engine for autonomous agent loops.

> [!NOTE]
> **Status: Experimental Research Prototype**  
> CouncilEngine is designed to explore verifiable multi-agent consensus, static code inspection, and offline rehearsal workflows. It provides formal receipts and verification boundaries for local developer loops and does not grant autonomous production deployment authority.

---

## 1. Origin & Architectural Role

CouncilEngine originated as the governance and verification sub-engine inside the [Pharmacy Fiduciary Commons (PBM)](https://github.com/Simultech369/Pharmacy-Fiduciary-Commons) ecosystem. It is designed to run either as a standalone Python engine or as a Git submodule (`tools/council`) consumed by downstream harnesses.

---

## 2. Workflows & Egress Boundaries

| Workflow Layer | Egress & Execution Posture | Key Modules |
| :--- | :--- | :--- |
| **Static Rehearsal & Batch Run** | **Strictly Offline / Zero Egress**: No network calls, no subprocess repository mutations, mock AST/diff validation only. | `sovereign_swebench_batch_runner.py`, `swebench_patch_synthesizer.py` |
| **Anti-Wrapper & Dead-Code Scanner** | **Local AST Only**: Analyzes repository Python AST for dead internal helpers, wrapper classification, and SLOC regression. | `anti_wrapper_audit.py` |
| **Consensus & Formal Verification** | **Deterministic Local Math**: Merkle proofs, dual-chain council verifier, and typed receipt envelopes. | `council_contracts.py`, `distributed_merkle_state_sync.py` |
| **Model Gateway & Adapters** | **Local / Adapter Surface**: Optional local Ollama or mock test adapters. External network calls require explicit provider configuration and are blocked during standard offline test runs. | `model_egress_choke_point.py`, `model_gateway_log_guard.py` |

---

## 3. Setup & Verification

### Prerequisites
* Python 3.10+ (tested on Python 3.12)
* `pytest` (optional: `anyio`, `asyncio` plugins for async tests)

### Quick Start & Test Execution
```powershell
# Clone the repository
git clone https://github.com/Simultech369/CouncilEngine.git
cd CouncilEngine

# Run the full offline test suite (406 tests, zero external calls)
python -m pytest

# Run the anti-wrapper regression gate
python -B anti_wrapper_audit.py --target-dir . --baseline-file ANTI_WRAPPER_BASELINE.json --fail-on-regression
```

---

## 4. Synthetic Rehearsal Example

```python
from sovereign_swebench_batch_runner import (
    SovereignSWEBenchBatchRunner,
    SovereignSWEBenchTask,
)

# Initialize offline batch runner (enforces STATIC_REHEARSAL_ONLY)
runner = SovereignSWEBenchBatchRunner(batch_id="demo-batch-001")

task = SovereignSWEBenchTask(
    task_id="task_sample_01",
    target_file="sample.py",
    search_block="def compute():\n    return False\n",
    replace_block="def compute():\n    return True\n",
    initial_file_content="def compute():\n    return False\n",
)

# Run static evaluation pipeline
receipt_envelope = runner.run_batch([task])
receipt = receipt_envelope.payload

print(f"Authority Scope: {receipt.authority_scope}")
print(f"Accepted: {receipt.static_accept_count}, Rejected: {receipt.rejected_count}")
assert receipt.production_authority is False
assert receipt.tests_executed is False
```

---

## 5. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
