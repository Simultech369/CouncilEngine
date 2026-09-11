import os
import shutil
import tempfile
import unittest
from council_contracts import ReviewHopTraceReceipt
from council_telemetry import CouncilTelemetryTracer
from council_verifier import CouncilReceiptVerifier, VerificationError

class TestCouncilTelemetry(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.tracer = CouncilTelemetryTracer(trace_storage_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_single_span_lifecycle(self):
        t_id, s_id = self.tracer.start_span(
            name="model.invocation",
            attributes={
                "llm.model_slug": "qwen/qwen-3.8-coder",
                "llm.provider": "alibabacloud",
                "route.compliance_tier": "HOSTED_NO_TRAIN"
            }
        )
        self.assertTrue(len(t_id) >= 16)
        self.assertTrue(len(s_id) >= 8)

        self.tracer.add_span_event(s_id, "token.first_received", {"chunk_index": 0})

        span_record = self.tracer.end_span(
            span_id=s_id,
            status_code="OK",
            additional_attributes={
                "llm.tokens.prompt": 512,
                "llm.tokens.completion": 128,
                "llm.cost_usd": 0.00015
            }
        )
        self.assertEqual(span_record.name, "model.invocation")
        self.assertEqual(span_record.status_code, "OK")
        self.assertEqual(span_record.attributes["llm.tokens.prompt"], 512)
        self.assertEqual(len(span_record.events), 1)
        self.assertGreaterEqual(span_record.duration_ms, 0.0)

    def test_multi_span_parent_child_trace(self):
        # Root span: council.convocation
        t_id, root_id = self.tracer.start_span(name="council.convocation")

        # Child span: sandbox.execution
        _, child_id = self.tracer.start_span(
            name="sandbox.execution",
            trace_id=t_id,
            parent_span_id=root_id,
            attributes={"sandbox.engine": "docker", "sandbox.network": "none"}
        )
        self.tracer.end_span(child_id, status_code="OK", additional_attributes={"test.exit_code": 0})

        # End root span
        self.tracer.end_span(root_id, status_code="OK", additional_attributes={"council.verdict": "APPROVED"})

        # Read back spans from trace CAS file
        spans = self.tracer.list_spans_for_trace(t_id)
        self.assertEqual(len(spans), 2)
        
        span_names = [s.name for s in spans]
        self.assertIn("sandbox.execution", span_names)
        self.assertIn("council.convocation", span_names)

        child_span = next(s for s in spans if s.name == "sandbox.execution")
        self.assertEqual(child_span.parent_span_id, root_id)

    def test_review_hop_trace_receipt_records_provenance_without_sandbox_overclaim(self):
        curr_dir = os.path.abspath(os.path.dirname(__file__))
        if os.path.exists(os.path.join(curr_dir, ".git")):
            repo_root = curr_dir
        else:
            repo_root = os.path.abspath(os.path.join(curr_dir, "..", ".."))
        cmd = self.tracer.build_command_record(
            command_argv=["python", "-m", "unittest", "tools/council/test_external_a2a_adapter.py"],
            executed=True,
            exit_code=0,
            stdout="OK\n",
            stderr="",
            duration_sec=0.25
        )

        env = self.tracer.seal_review_hop_trace(
            source_agent_id="codex",
            target_agent_id="antigravity",
            hop_kind="REVIEW_DISPOSITION",
            input_payload={"question": "review A2A trace receipt"},
            output_payload={"decision": "approve", "summary": "bounded local provenance"},
            repo_root=repo_root,
            command_records=[cmd],
            isolation_mode="LOCAL_SUBPROCESS_MOCK",
            network_isolated=False
        )

        CouncilReceiptVerifier.verify_envelope(env, ReviewHopTraceReceipt)
        payload = env.payload
        self.assertEqual(payload.source_agent_id, "codex")
        self.assertEqual(payload.target_agent_id, "antigravity")
        self.assertEqual(payload.hop_kind, "REVIEW_DISPOSITION")
        self.assertEqual(payload.isolation_mode, "LOCAL_SUBPROCESS_MOCK")
        self.assertEqual(payload.git_observation_status, "OBSERVED")
        self.assertNotIn("est/A2AProtocolEngine.test.js", payload.dirty_files)
        self.assertRegex(payload.reviewed_content_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(payload.toolchain_manifest_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(payload.execution_environment_hash_sha256, r"^[0-9a-f]{64}$")
        self.assertFalse(payload.network_isolated)
        self.assertTrue(payload.provenance_only)
        self.assertFalse(payload.remote_execution_permitted)
        self.assertFalse(payload.production_execution_claimed)
        self.assertFalse(payload.audit_replacement_claimed)
        self.assertEqual(payload.commands[0].exit_code, 0)
        self.assertEqual(payload.commands[0].stdout_sha256, self.tracer._sha256_text("OK\n"))
        self.assertNotIn("OK\n", payload.model_dump_json())

        spans = self.tracer.list_spans_for_trace(payload.trace_id)
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].attributes["receipt.payload_sha256"], env.payload_sha256)

    def test_review_hop_trace_rejects_mock_network_isolation_claim(self):
        cmd = self.tracer.build_command_record(
            command_argv=["python", "-m", "unittest"],
            executed=True,
            exit_code=0,
            stdout="OK",
            stderr="",
            duration_sec=0.1
        )

        with self.assertRaises(ValueError) as ctx:
            self.tracer.seal_review_hop_trace(
                source_agent_id="codex",
                target_agent_id="antigravity",
                hop_kind="LOCAL_GATE",
                input_payload={"gate": "unit"},
                output_payload={"status": "passed"},
                command_records=[cmd],
                isolation_mode="LOCAL_SUBPROCESS_MOCK",
                network_isolated=True
            )
        self.assertIn("LOCAL_SUBPROCESS_MOCK cannot claim network isolation", str(ctx.exception))

    def test_review_hop_trace_rejects_unsupported_docker_isolation_claim(self):
        with self.assertRaises(ValueError) as ctx:
            self.tracer.seal_review_hop_trace(
                source_agent_id="codex",
                target_agent_id="antigravity",
                hop_kind="LOCAL_GATE",
                input_payload={"gate": "unit"},
                output_payload={"status": "passed"},
                command_records=[],
                isolation_mode="DOCKER_CONTAINER_ENFORCED",
                network_isolated=True
            )
        self.assertIn("DOCKER_CONTAINER_ENFORCED requires a verified sandbox receipt", str(ctx.exception))

    def test_read_only_review_hop_trace_rejects_executed_commands(self):
        cmd = self.tracer.build_command_record(
            command_argv=["python", "-m", "unittest"],
            executed=True,
            exit_code=0,
            stdout="OK",
            stderr="",
            duration_sec=0.1
        )

        with self.assertRaises(ValueError) as ctx:
            self.tracer.seal_review_hop_trace(
                source_agent_id="codex",
                target_agent_id="antigravity",
                hop_kind="A2A_HANDOFF",
                input_payload={"handoff": "state"},
                output_payload={"status": "read"},
                command_records=[cmd],
                isolation_mode="READ_ONLY_NO_EXECUTION",
                network_isolated=False
            )
        self.assertIn("READ_ONLY_NO_EXECUTION cannot include executed command records", str(ctx.exception))

    def test_command_record_rejects_non_executed_artifacts(self):
        with self.assertRaises(ValueError) as ctx:
            self.tracer.build_command_record(
                command_argv=["python", "-m", "unittest"],
                executed=False,
                exit_code=0,
                stdout="OK"
            )
        self.assertIn("non-executed command records cannot include execution artifacts", str(ctx.exception))

    def test_command_record_requires_exit_code_when_executed(self):
        with self.assertRaises(ValueError) as ctx:
            self.tracer.build_command_record(
                command_argv=["python", "-m", "unittest"],
                executed=True,
                stdout="OK"
            )
        self.assertIn("executed command records must include exit_code", str(ctx.exception))

    def test_porcelain_z_parser_preserves_leading_filename_character(self):
        dirty = self.tracer._parse_porcelain_z(b" M test/A2AProtocolEngine.test.js\0")
        self.assertEqual(dirty, ["test/A2AProtocolEngine.test.js"])

    def test_git_state_fails_closed_when_status_unavailable(self):
        def fake_text(root, args, timeout=5):
            if args == ["rev-parse", "HEAD"]:
                return True, "a" * 40
            if args == ["branch", "--show-current"]:
                return True, "main"
            return False, ""

        def fake_bytes(root, args, timeout=5):
            return False, b""

        self.tracer._run_git_text = fake_text
        self.tracer._run_git_bytes = fake_bytes
        state = self.tracer.collect_git_state(os.getcwd())
        self.assertEqual(state["git_observation_status"], "UNAVAILABLE")
        self.assertTrue(state["working_tree_dirty"])
        self.assertEqual(state["dirty_files"], ["UNKNOWN_GIT_STATUS"])

    def test_semantic_verifier_rejects_command_hash_mismatch(self):
        cmd = self.tracer.build_command_record(
            command_argv=["python", "-m", "unittest"],
            executed=True,
            exit_code=0,
            stdout="OK",
            stderr="",
            duration_sec=0.1
        )
        env = self.tracer.seal_review_hop_trace(
            source_agent_id="codex",
            target_agent_id="antigravity",
            hop_kind="LOCAL_GATE",
            input_payload={"gate": "unit"},
            output_payload={"status": "passed"},
            command_records=[cmd],
            isolation_mode="LOCAL_SUBPROCESS_MOCK",
            network_isolated=False
        )
        forged_cmd = env.payload.commands[0].model_copy(update={"command_sha256": "0" * 64})
        forged_payload = env.payload.model_copy(update={"commands": [forged_cmd]})
        forged_payload = forged_payload.model_copy(update={
            "command_manifest_sha256": self.tracer._sha256_json([forged_cmd.model_dump()])
        })
        forged_payload = forged_payload.model_copy(update={
            "execution_environment_hash_sha256": self.tracer._sha256_json({
                "git_head_commit": forged_payload.git_head_commit,
                "git_branch": forged_payload.git_branch,
                "git_observation_status": forged_payload.git_observation_status,
                "working_tree_dirty": forged_payload.working_tree_dirty,
                "dirty_files": forged_payload.dirty_files,
                "reviewed_content_sha256": forged_payload.reviewed_content_sha256,
                "command_manifest_sha256": forged_payload.command_manifest_sha256,
                "toolchain_manifest_sha256": forged_payload.toolchain_manifest_sha256,
                "isolation_mode": forged_payload.isolation_mode,
                "network_isolated": forged_payload.network_isolated,
            })
        })
        forged_env = env.model_copy(update={
            "payload": forged_payload,
            "payload_sha256": forged_payload.compute_canonical_sha256()
        })
        forged_env = forged_env.model_copy(update={
            "envelope_sha256": self.tracer._sha256_text(
                f"{forged_env.contract_version}:{forged_env.receipt_type}:{forged_env.payload_sha256}:{forged_env.created_at}"
            )
        })
        with self.assertRaises(VerificationError):
            CouncilReceiptVerifier.verify_envelope(forged_env, ReviewHopTraceReceipt)

    def test_start_span_rejects_invalid_names(self):
        with self.assertRaises(ValueError):
            self.tracer.start_span(name="invalid span name")
        with self.assertRaises(ValueError):
            self.tracer.start_span(name="invalid/span/name")
        
        # Valid names should not raise
        self.tracer.start_span(name="valid.span-name_123")

    def test_build_command_record_redacts_sensitive_flags(self):
        cmd = self.tracer.build_command_record(
            command_argv=["curl", "-k", "secret1", "--key", "secret2", "--key=secret3", "--authorization", "secret4", "https://api.example.com"],
            executed=False
        )
        argv = cmd.command_argv
        self.assertIn("[REDACTED]", argv)
        self.assertNotIn("secret1", argv)
        self.assertNotIn("secret2", argv)
        self.assertNotIn("--key=secret3", argv)
        self.assertIn("--key=[REDACTED]", argv)
        self.assertNotIn("secret4", argv)

if __name__ == "__main__":
    unittest.main()
