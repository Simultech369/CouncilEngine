#!/usr/bin/env python3
"""
Unit Tests for C2C Semantic Bus & Dizzy Trajectory Bridge
==========================================================
Tests:
1. Ingestion of Dizzy canonical golden_trajectories.json into Dream-RSI.
2. Replay of multi-step execution traces with prompt variant scoring.
3. Cache-to-Cache (C2C) KV-Cache projection and layer-gating across heterogeneous models.
4. Constitutional airlock verification gate (tamper detection & raw tensor leak rejection).
"""

import json
import os
import unittest
import hashlib
from dream_rsi_replay_engine import DreamRSIReplayEngine, DossierCorpus, ReplayEpisode
from c2c_semantic_bus import (
    CacheFuser,
    C2CAirlockVerificationGate,
    KVCacheTensorShape,
    AirlockBreachError,
    C2CFusionReceipt,
)
from council_contracts import ReceiptEnvelope
LOCAL_FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "golden_trajectories.json")
DIZZY_GOLDEN_TRAJECTORIES = os.environ.get("DIZZY_GOLDEN_TRAJECTORIES", LOCAL_FIXTURE_PATH)


class TestDizzyTrajectoryBridge(unittest.TestCase):
    """Verifies ingestion and replay of Dizzy runtime trajectories in CouncilEngine."""

    def setUp(self):
        self.engine = DreamRSIReplayEngine()

    def test_load_dizzy_golden_trajectories(self):
        self.assertTrue(os.path.isfile(DIZZY_GOLDEN_TRAJECTORIES), "Dizzy golden trajectories file missing")
        episodes = self.engine.corpus.load_from_trajectories(DIZZY_GOLDEN_TRAJECTORIES)

        self.assertEqual(len(episodes), 5)
        expected_ids = {
            "traj-golden_context_assembly",
            "traj-golden_route_plan_execution",
            "traj-golden_stream_stall_guard",
            "traj-golden_statem_plan_execute_verify",
            "traj-golden_review_cycle_synthesis",
        }
        actual_ids = {ep.episode_id for ep in episodes}
        self.assertEqual(actual_ids, expected_ids)

        for ep in episodes:
            self.assertEqual(ep.review_scope, "trajectory_execution")
            self.assertEqual(ep.model_slug, "dizzy_runtime_agent")
            self.assertTrue(ep.metadata.get("step_count", 0) >= 3)
            self.assertEqual(ep.metadata.get("outcome"), "success")

    def test_replay_trajectories_with_prompt_variant_scores_deltas(self):
        baseline_prompt = "Perform standard review."
        shielded_prompt = "Enforce _startRound, updateCreditLimit, and registerVoterWithSignature."

        report_env = self.engine.replay_trajectories(
            trajectories_path=DIZZY_GOLDEN_TRAJECTORIES,
            variant_name="shielded-v1",
            new_prompt_text=shielded_prompt,
            baseline_prompt_text=baseline_prompt,
        )

        self.assertIsNotNone(report_env)
        report = report_env.payload
        self.assertEqual(report.episode_count, 5)
        self.assertEqual(len(report.results), 5)
        # Shielded prompt should score higher than plain baseline
        self.assertGreaterEqual(report.variant_mean_score, report.baseline_mean_score)
        self.assertGreaterEqual(report.delta, 0.0)


class TestC2CSemanticBus(unittest.TestCase):
    """Verifies Cache-to-Cache (C2C) KV-Cache projection and layer gating."""

    def setUp(self):
        self.fuser = CacheFuser(default_threshold=0.60)
        self.qwen_shape = KVCacheTensorShape(
            model_slug="qwen2.5-coder:7b",
            num_layers=28,
            num_heads=28,
            head_dim=128,
            sequence_length=512,
            dtype="bfloat16",
            cache_tensor_sha256=hashlib.sha256(b"qwen_kv_cache_tensor_bytes").hexdigest(),
        )
        self.deepseek_shape = KVCacheTensorShape(
            model_slug="deepseek-coder:6.7b",
            num_layers=32,
            num_heads=32,
            head_dim=128,
            sequence_length=512,
            dtype="bfloat16",
            cache_tensor_sha256=hashlib.sha256(b"deepseek_kv_cache_tensor_bytes").hexdigest(),
        )

    def test_layer_gating_excludes_early_layers_includes_deep_layers(self):
        active_layers, weights = self.fuser.compute_layer_gates(
            num_layers=32,
            source_slug="qwen2.5-coder:7b",
            target_slug="deepseek-coder:6.7b",
            threshold=0.60,
        )

        # Early syntax layers (0-5) must not be gated
        for early in range(5):
            self.assertNotIn(early, active_layers)
            self.assertLess(weights[str(early)], 0.60)

        # Deep semantic layers (20-31) must be gated
        for deep in range(20, 32):
            self.assertIn(deep, active_layers)
            self.assertGreaterEqual(weights[str(deep)], 0.60)

        self.assertGreater(len(active_layers), 10)

    def test_c2c_projection_emits_sealed_receipt(self):
        fused_hash, receipt_env = self.fuser.project_and_fuse(
            source_shape=self.qwen_shape,
            target_shape=self.deepseek_shape,
        )

        self.assertIsNotNone(fused_hash)
        self.assertIsNotNone(receipt_env)
        self.assertEqual(receipt_env.receipt_type, "C2CFusionReceipt")

        payload = receipt_env.payload
        self.assertEqual(payload.source_model, "qwen2.5-coder:7b")
        self.assertEqual(payload.target_model, "deepseek-coder:6.7b")
        self.assertEqual(payload.speedup_factor, 2.50)
        self.assertTrue(payload.gated_layer_count > 0)
        self.assertEqual(payload.fused_cache_sha256, fused_hash)

    def test_airlock_verification_accepts_valid_receipt_and_legible_artifact(self):
        _, receipt_env = self.fuser.project_and_fuse(
            source_shape=self.qwen_shape,
            target_shape=self.deepseek_shape,
        )

        compliant_diff = "+++ b/contracts/PBMRebateTreasury.sol\n@@ -10,3 +10,4 @@\n+ // Invariant verified"
        # Should pass without exception
        C2CAirlockVerificationGate.assert_airlock_compliance(receipt_env, compliant_diff)

    def test_airlock_verification_rejects_empty_artifact(self):
        _, receipt_env = self.fuser.project_and_fuse(
            source_shape=self.qwen_shape,
            target_shape=self.deepseek_shape,
        )

        with self.assertRaises(AirlockBreachError) as ctx:
            C2CAirlockVerificationGate.assert_airlock_compliance(receipt_env, "   ")
        self.assertIn("Airlock Violation: C2C fusion produced no verifiable", str(ctx.exception))

    def test_airlock_verification_rejects_raw_tensor_leak(self):
        _, receipt_env = self.fuser.project_and_fuse(
            source_shape=self.qwen_shape,
            target_shape=self.deepseek_shape,
        )

        leaked_artifact = "Patch summary: fixed buffer with 0x[tensor_raw_8fa72] latent dump"
        with self.assertRaises(AirlockBreachError) as ctx:
            C2CAirlockVerificationGate.assert_airlock_compliance(receipt_env, leaked_artifact)
        self.assertIn("Unsanitized raw tensor bytes leaked", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
