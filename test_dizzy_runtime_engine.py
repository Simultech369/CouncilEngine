import json
import os
import shutil
import tempfile
import unittest
from dizzy_runtime_engine import DizzyRuntimeEngine

class TestDizzyRuntimeEngine(unittest.TestCase):

    def setUp(self):
        self.workspace = tempfile.mkdtemp()
        self.engine = DizzyRuntimeEngine(workspace_root=self.workspace, max_context_turns=6)

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_virtual_root_jail_and_path_traversal(self):
        # 1. Valid write and read within workspace
        ok_w, msg_w = self.engine.execute_filesystem_write("src/app.py", "print('hello world')")
        self.assertTrue(ok_w)

        ok_r, content = self.engine.execute_filesystem_read("src/app.py")
        self.assertTrue(ok_r)
        self.assertEqual(content, "print('hello world')")

        # 2. Path traversal attack attempt
        ok_trav, msg_trav = self.engine.execute_filesystem_read("../../secret.txt")
        self.assertFalse(ok_trav)
        self.assertIn("Path escapes virtual workspace jail", msg_trav)

        # 3. Protected credential path attempt
        ok_cred, msg_cred = self.engine.execute_filesystem_read(".ssh/id_rsa")
        self.assertFalse(ok_cred)
        self.assertIn("Protected security path", msg_cred)

    def test_single_use_hmac_nonce(self):
        tool_name = "edit_file"
        args = {"path": "src/app.py", "content": "print('patched')"}

        nonce = self.engine.generate_single_use_nonce(tool_name, args)
        self.assertTrue(nonce.startswith("NONCE_"))

        # 1. Valid first consumption
        valid_first = self.engine.verify_and_consume_nonce(tool_name, args, nonce)
        self.assertTrue(valid_first)

        # 2. Replay attack attempt
        valid_replay = self.engine.verify_and_consume_nonce(tool_name, args, nonce)
        self.assertFalse(valid_replay)

        # 3. Argument tampering attempt
        tampered_args = {"path": "src/app.py", "content": "print('malicious')"}
        nonce_tamper = self.engine.generate_single_use_nonce(tool_name, args)
        valid_tamper = self.engine.verify_and_consume_nonce(tool_name, tampered_args, nonce_tamper)
        self.assertFalse(valid_tamper)

    def test_sliding_window_memory_compression(self):
        # Append 7 turns (exceeds max_context_turns=6)
        for i in range(7):
            self.engine.append_turn("user" if i % 2 == 0 else "assistant", f"Message turn {i}")

        self.assertTrue(self.engine.should_compress_memory())

        snap_env, retained = self.engine.compress_episodic_memory()
        self.assertEqual(snap_env.payload.retained_facts_count, 3)
        self.assertEqual(snap_env.payload.expired_facts_count, 4)
        self.assertEqual(len(retained), 3)
        self.assertFalse(self.engine.should_compress_memory())

    def test_ndjson_event_formatting(self):
        event_str = self.engine.format_ndjson_event("tool.call.completed", {"tool": "edit_file", "success": True})
        self.assertTrue(event_str.endswith("\n"))
        event_obj = json.loads(event_str)
        self.assertEqual(event_obj["event_type"], "tool.call.completed")
        self.assertEqual(event_obj["payload"]["tool"], "edit_file")

if __name__ == "__main__":
    unittest.main()
