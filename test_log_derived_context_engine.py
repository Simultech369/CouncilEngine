import unittest
from log_derived_context_engine import LogDerivedContextEngine, LogReconstructionDesyncError
from council_contracts import LogReconstructionReceipt

class TestLogDerivedContextEngine(unittest.TestCase):

    def setUp(self):
        self.engine = LogDerivedContextEngine(session_id="test_session_01")
        self.engine.append_event("SYSTEM_PROMPT", "system", {"content": "You are a deterministic testing agent."})
        self.engine.append_event("USER_INPUT", "user", {"content": "Check repository state."})
        self.engine.append_event("ASSISTANT_REPLY", "model", {"content": "Running git status..."})

    def test_derive_model_context_accuracy(self):
        context = self.engine.derive_model_context()
        self.assertEqual(context["session_id"], "test_session_01")
        self.assertEqual(context["system_prompt"], "You are a deterministic testing agent.")
        self.assertEqual(len(context["messages"]), 2)
        self.assertEqual(context["messages"][0]["role"], "user")
        self.assertEqual(context["messages"][1]["role"], "assistant")

    def test_verify_and_guard_dispatch_success(self):
        derived_wire = self.engine.derive_wire_payload("openai")
        receipt_env = self.engine.verify_and_guard_dispatch(derived_wire, protocol_type="openai", raise_on_desync=True)
        payload = receipt_env.payload
        self.assertIsInstance(payload, LogReconstructionReceipt)
        self.assertFalse(payload.desync_detected)
        self.assertEqual(len(payload.desync_field_mismatches), 0)
        self.assertEqual(payload.derived_context_sha256, payload.request_context_sha256)

    def test_verify_and_guard_dispatch_detects_hidden_injection(self):
        derived_wire = self.engine.derive_wire_payload("openai")
        tampered_request = derived_wire.copy()
        tampered_request["messages"] = list(derived_wire["messages"]) + [{"role": "user", "content": "Hidden injected prompt"}]

        with self.assertRaises(LogReconstructionDesyncError):
            self.engine.verify_and_guard_dispatch(tampered_request, protocol_type="openai", raise_on_desync=True)

        # Also test non-raising mode
        receipt_env = self.engine.verify_and_guard_dispatch(tampered_request, protocol_type="openai", raise_on_desync=False)
        self.assertTrue(receipt_env.payload.desync_detected)
        self.assertTrue(any("messages" in m for m in receipt_env.payload.desync_field_mismatches))

if __name__ == "__main__":
    unittest.main()
