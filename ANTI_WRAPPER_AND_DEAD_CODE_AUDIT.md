# Anti-Wrapper Theatre, Dead-Code & ΔLOC Audit Report
**Target**: `C:\Users\Josh\Desktop\CouncilEngine`  
**Python Files Scanned**: 139  

## 1. ΔLOC & Volume Breakdown

| Layer | Files | Total Lines | Code Lines (SLOC) | Comments | Blanks |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Production** | 72 | 18297 | 15715 | 428 | 2154 |
| **Tests** | 67 | 9136 | 7673 | 222 | 1241 |
| **Total** | **139** | **27433** | **23388** | **650** | **3395** |

**Test-to-Production Code Ratio**: `0.488` (Target: >= 0.50)

## 2. Dead-Code & Unused Helper Audit
Total unreferenced internal helpers detected: **0**

✅ **Zero unreferenced internal helpers detected.** All defined private symbols have active call sites.

## 3. Wrapper Theatre & Compatibility Shims Audit
- Naked Wrappers (no contract/invariants): **17**
- Documented Compatibility Shims: **1**

| File | Function | Target Called | Classification | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `a2a_protocol_engine.py` | `get_public_key` | `get` | `NAKED_WRAPPER` | `` |
| `a2a_protocol_engine.py` | `list_agents` | `sorted` | `NAKED_WRAPPER` | `` |
| `a2a_protocol_engine.py` | `get_mailbox` | `get` | `NAKED_WRAPPER` | `` |
| `council_api_server.py` | `_safe_sse_token` | `replace` | `NAKED_WRAPPER` | `Keeps SSE metadata single-line so event boundaries remain unambiguous.` |
| `distributed_merkle_state_sync.py` | `get_merkle_root_cid` | `get_merkle_root` | `NAKED_WRAPPER` | `Alias for get_merkle_root to provide consistent CID retrieval.` |
| `dizzy_runtime_engine.py` | `append_turn` | `append` | `NAKED_WRAPPER` | `` |
| `dizzy_runtime_engine.py` | `emit_streaming_event_ndjson` | `format_ndjson_event` | `NAKED_WRAPPER` | `` |
| `external_a2a_adapter.py` | `create_agent_card` | `AgentCard` | `NAKED_WRAPPER` | `Constructs a certified read-only Agent Card.` |
| `lifecycle_hooks.py` | `_record_webhook_dispatch` | `extend` | `NAKED_WRAPPER` | `` |
| `model_gateway.py` | `dispatch_call` | `invoke_with_resilience` | `COMPATIBILITY_SHIM` | `Backward-compatible adapter. New production callers should use
invoke_with_resilience so the gateway` |
| `p2p_gossip_transport.py` | `add_peer` | `add` | `NAKED_WRAPPER` | `Registers a known peer address for gossip replication.` |
| `p2p_gossip_transport.py` | `_canonical_message_bytes` | `encode` | `NAKED_WRAPPER` | `` |
| `shared_memory.py` | `record_learned_invariant` | `record_working_practice` | `NAKED_WRAPPER` | `Adds a working best practice or triggers rule proposal.` |
| `shared_memory.py` | `get_invariants_prompt_context` | `get_complete_invariants_and_practices_context` | `NAKED_WRAPPER` | `Returns the clearly partitioned context containing Formal Rules & Working Practices.` |
| `sovereign_swebench_batch_runner.py` | `_bounded_ref` | `_hashed_ref` | `NAKED_WRAPPER` | `Return a redacted reference for untrusted operator metadata.

The current runner treats all external` |
| `sovereign_swebench_batch_runner.py` | `_safe_path_ref` | `_hashed_ref` | `NAKED_WRAPPER` | `` |
| `task_router.py` | `role_profiles` | `dict` | `NAKED_WRAPPER` | `` |
| `task_router.py` | `_normalize_text` | `sub` | `NAKED_WRAPPER` | `` |

## 4. Baseline Regression Check
Status: **PASS**

| Metric | Baseline | Current | Delta | Status | Reason |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `unused_internal_helpers` | `0` | `0` | `0` | `PASS` | No regression. |
| `naked_wrappers` | `17` | `17` | `0` | `PASS` | No regression. |
| `production_code_lines` | `15715` | `15715` | `0` | `PASS` | No production SLOC growth. |
