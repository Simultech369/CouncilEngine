"""
Tests for the Dream-RSI Offline Replay Engine.

Validates:
  1. DossierCorpus can parse the real reviews/ directory
  2. ReplayEpisode construction and immutability
  3. Default structural evaluator scoring logic
  4. DreamRSIReplayEngine produces sealed ReceiptEnvelope reports
  5. Scope and model filtering
  6. Edge cases: empty corpus, no-match filters
"""

import hashlib
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dream_rsi_replay_engine import (
    DossierCorpus,
    DreamReplayReport,
    DreamRSIReplayEngine,
    EpisodeReplayResult,
    ReplayEpisode,
    _default_structural_evaluator,
    _sha256,
)
from council_contracts import ReceiptEnvelope


# ──────────────────────────────────────────────────────────────────
def _find_real_reviews_dir() -> str:
    # 1. Submodule layout: PBMRebateTreasuryFinal/tools/council -> parent PBM root
    cand1 = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "reviews")
    if os.path.isdir(cand1):
        return cand1
    # 2. Standalone Desktop layout: Desktop/CouncilEngine -> sibling Desktop/PBMRebateTreasuryFinal/reviews
    cand2 = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "PBMRebateTreasuryFinal", "reviews"))
    if os.path.isdir(cand2):
        return cand2
    return cand1

REAL_REVIEWS_DIR = _find_real_reviews_dir()


def _make_temp_reviews_dir():
    """Create a temporary reviews directory with synthetic dossiers."""
    tmpdir = tempfile.mkdtemp(prefix="dream_rsi_test_")

    # Synthetic swarm loop dossier pair
    swarm_metadata = {
        "model_slug": "test-model-alpha",
        "review_scope": "solvency",
        "timestamp": "2026-09-01T12:00:00Z",
    }
    swarm_response = """
# Solvency Review Findings

## Critical Finding: Epoch Escrow Mismatch
- **Severity**: High
- **Line**: Line 142 in PBMRebateTreasury.sol
- **Issue**: The `epochEscrow` mapping is not decremented during `resolveClaim`.
- **Recommendation**: Should decrement `epochEscrow[epoch]` by the claim amount.

## Medium Finding: Missing Zero-Check
- **Severity**: Medium
- **Line**: Line 87
- **Recommendation**: Consider adding a zero-amount guard.
"""

    with open(os.path.join(tmpdir, "multimodal_swarm_loop-solvency.json"), "w") as f:
        json.dump(swarm_metadata, f)
    with open(os.path.join(tmpdir, "multimodal_swarm_loop-solvency.md"), "w") as f:
        f.write(swarm_response)

    # Synthetic standalone review
    review_text = """
# Architecture Review

## Informational: Module Boundaries
The repository architecture separates concerns into contract, governance, and frontend layers.
Should consider adding explicit interface contracts between modules.

## Low: Missing Type Annotations
Line 23 in model_gateway.py lacks type hints.
Recommend adding type annotations for maintainability.
"""
    with open(os.path.join(tmpdir, "test-architecture-review.md"), "w") as f:
        f.write(review_text)

    # Synthetic ZK review with phantom path (should fail hallucination check)
    zk_review = """
# ZK Privacy Review

## Critical: Privacy Leak in contracts/drafts/NullifierRegistry.sol
The nullifier commitment scheme at line 45 leaks the preimage through public logs.
Recommend using a proper zero knowledge proof circuit instead.
"""
    with open(os.path.join(tmpdir, "zero_zk-packet-review.md"), "w") as f:
        f.write(zk_review)

    # Adversarial: empty review file (should be skipped)
    with open(os.path.join(tmpdir, "empty-review.md"), "w") as f:
        f.write("")

    return tmpdir


@pytest.fixture
def temp_reviews_dir():
    tmpdir = _make_temp_reviews_dir()
    yield tmpdir
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


# ──────────────────────────────────────────────────────────────────
# Tests: DossierCorpus
# ──────────────────────────────────────────────────────────────────

class TestDossierCorpus:

    def test_loads_synthetic_episodes(self, temp_reviews_dir):
        corpus = DossierCorpus(temp_reviews_dir)
        episodes = corpus.load_episodes()
        # Should load the swarm pair + standalone review + ZK review (not empty)
        assert len(episodes) >= 2

    def test_episode_immutability(self, temp_reviews_dir):
        corpus = DossierCorpus(temp_reviews_dir)
        episodes = corpus.load_episodes()
        assert len(episodes) > 0
        episode = episodes[0]
        with pytest.raises(Exception):
            episode.response_text = "mutated"  # type: ignore[misc]

    def test_scope_extraction_swarm(self, temp_reviews_dir):
        corpus = DossierCorpus(temp_reviews_dir)
        episodes = corpus.load_episodes()
        swarm_episodes = [ep for ep in episodes if ep.source_file.startswith("multimodal_swarm")]
        assert len(swarm_episodes) >= 1
        assert swarm_episodes[0].review_scope == "solvency"

    def test_model_slug_extraction(self, temp_reviews_dir):
        corpus = DossierCorpus(temp_reviews_dir)
        episodes = corpus.load_episodes()
        swarm_episodes = [ep for ep in episodes if ep.source_file.startswith("multimodal_swarm")]
        assert len(swarm_episodes) >= 1
        assert swarm_episodes[0].model_slug == "test-model-alpha"

    def test_scope_filtering(self, temp_reviews_dir):
        corpus = DossierCorpus(temp_reviews_dir)
        solvency_episodes = corpus.load_episodes_by_scope("solvency")
        assert all(ep.review_scope == "solvency" for ep in solvency_episodes)

    def test_model_filtering(self, temp_reviews_dir):
        corpus = DossierCorpus(temp_reviews_dir)
        alpha_episodes = corpus.load_episodes_by_model("test-model-alpha")
        assert all(ep.model_slug == "test-model-alpha" for ep in alpha_episodes)

    def test_skips_empty_files(self, temp_reviews_dir):
        corpus = DossierCorpus(temp_reviews_dir)
        episodes = corpus.load_episodes()
        source_files = [ep.source_file for ep in episodes]
        assert "empty-review.md" not in source_files

    def test_nonexistent_directory_raises(self):
        with pytest.raises(FileNotFoundError):
            DossierCorpus("/nonexistent/path/to/reviews")


# ──────────────────────────────────────────────────────────────────
# Tests: Default Structural Evaluator
# ──────────────────────────────────────────────────────────────────

class TestDefaultEvaluator:

    def _make_episode(self, response: str, scope: str = "solvency") -> ReplayEpisode:
        return ReplayEpisode(
            episode_id="test-episode",
            source_file="test.md",
            review_scope=scope,
            model_slug="test-model",
            original_prompt_sha256=_sha256("test"),
            response_text=response,
            response_sha256=_sha256(response),
            metadata={},
        )

    def test_high_quality_response_scores_well(self):
        response = """
        ## Critical Finding: SQL Injection at Line 42
        Severity: High
        The query at line 42 is vulnerable to SQL injection.
        Recommendation: Use parameterized queries instead.
        This affects the solvency verification module.
        """
        episode = self._make_episode(response)
        scores = _default_structural_evaluator(episode, "test prompt")
        assert scores["has_findings"] == 1.0
        assert scores["has_severity"] == 1.0
        assert scores["has_line_refs"] == 1.0
        assert scores["has_recommendation"] == 1.0
        assert scores["no_hallucinated_files"] == 1.0
        assert scores["has_scope_alignment"] == 1.0

    def test_empty_response_scores_poorly(self):
        episode = self._make_episode("Everything looks good. No problems detected.")
        scores = _default_structural_evaluator(episode, "test prompt")
        assert scores["has_findings"] == 0.0
        assert scores["has_severity"] == 0.0
        assert scores["has_line_refs"] == 0.0

    def test_hallucinated_path_detected(self):
        response = "Found vulnerability in contracts/drafts/Token.sol at line 10"
        episode = self._make_episode(response)
        scores = _default_structural_evaluator(episode, "test prompt")
        assert scores["no_hallucinated_files"] == 0.0

    def test_scope_alignment_zk(self):
        response = "The zero knowledge nullifier scheme has a privacy concern."
        episode = self._make_episode(response, scope="zk")
        scores = _default_structural_evaluator(episode, "test prompt")
        assert scores["has_scope_alignment"] == 1.0

    def test_scope_alignment_mismatch(self):
        response = "The React component renders correctly."
        episode = self._make_episode(response, scope="solvency")
        scores = _default_structural_evaluator(episode, "test prompt")
        assert scores["has_scope_alignment"] == 0.0


# ──────────────────────────────────────────────────────────────────
# Tests: DreamRSIReplayEngine
# ──────────────────────────────────────────────────────────────────

class TestDreamRSIReplayEngine:

    def test_replay_produces_sealed_envelope(self, temp_reviews_dir):
        engine = DreamRSIReplayEngine(reviews_dir=temp_reviews_dir)
        envelope = engine.replay_with_variant(
            variant_name="test-variant",
            new_prompt_text="Review this code for solvency issues.",
        )
        assert isinstance(envelope, ReceiptEnvelope)
        assert envelope.receipt_type == "DreamReplayReport"
        assert envelope.payload_sha256
        assert envelope.envelope_sha256

    def test_report_structure(self, temp_reviews_dir):
        engine = DreamRSIReplayEngine(reviews_dir=temp_reviews_dir)
        envelope = engine.replay_with_variant(
            variant_name="test-variant",
            new_prompt_text="Prompt text v2",
        )
        report = envelope.payload
        assert isinstance(report, DreamReplayReport)
        assert report.variant_name == "test-variant"
        assert report.episode_count >= 2
        assert len(report.results) == report.episode_count
        assert report.baseline_mean_score >= 0.0
        assert report.variant_mean_score >= 0.0

    def test_scope_filter(self, temp_reviews_dir):
        engine = DreamRSIReplayEngine(reviews_dir=temp_reviews_dir)
        envelope = engine.replay_with_variant(
            variant_name="solvency-only",
            new_prompt_text="Solvency prompt",
            scope_filter="solvency",
        )
        report = envelope.payload
        for result in report.results:
            assert "solvency" in result.notes

    def test_max_episodes_cap(self, temp_reviews_dir):
        engine = DreamRSIReplayEngine(reviews_dir=temp_reviews_dir)
        envelope = engine.replay_with_variant(
            variant_name="capped",
            new_prompt_text="Test",
            max_episodes=1,
        )
        assert envelope.payload.episode_count == 1

    def test_no_episodes_raises(self, temp_reviews_dir):
        engine = DreamRSIReplayEngine(reviews_dir=temp_reviews_dir)
        with pytest.raises(ValueError, match="No replay episodes found"):
            engine.replay_with_variant(
                variant_name="empty",
                new_prompt_text="Test",
                scope_filter="nonexistent_scope",
            )

    def test_custom_evaluator(self, temp_reviews_dir):
        def always_perfect(episode, prompt):
            return {"perfect_score": 1.0}

        engine = DreamRSIReplayEngine(
            reviews_dir=temp_reviews_dir,
            evaluator_fn=always_perfect,
        )
        envelope = engine.replay_with_variant(
            variant_name="perfect",
            new_prompt_text="Test",
        )
        assert envelope.payload.variant_mean_score == 1.0

    def test_delta_computation(self, temp_reviews_dir):
        engine = DreamRSIReplayEngine(reviews_dir=temp_reviews_dir)
        envelope = engine.replay_with_variant(
            variant_name="delta-test",
            new_prompt_text="Test prompt",
            baseline_prompt_text="Baseline prompt",
        )
        report = envelope.payload
        expected_delta = round(report.variant_mean_score - report.baseline_mean_score, 6)
        assert report.delta == expected_delta


# ──────────────────────────────────────────────────────────────────
# Tests: Real Corpus Integration (conditional on reviews/ existing)
# ──────────────────────────────────────────────────────────────────

@pytest.mark.skipif(
    not os.path.isdir(REAL_REVIEWS_DIR),
    reason="Real reviews/ directory not available"
)
class TestRealCorpus:

    def test_loads_real_episodes(self):
        corpus = DossierCorpus(REAL_REVIEWS_DIR)
        episodes = corpus.load_episodes()
        # We know the reviews/ dir has ~99 files, should parse many
        assert len(episodes) >= 10, f"Expected >= 10 episodes, got {len(episodes)}"

    def test_real_replay_runs(self):
        engine = DreamRSIReplayEngine(reviews_dir=REAL_REVIEWS_DIR)
        envelope = engine.replay_with_variant(
            variant_name="real-corpus-baseline",
            new_prompt_text="default baseline",
            max_episodes=5,
        )
        report = envelope.payload
        assert report.episode_count == 5
        assert report.variant_mean_score >= 0.0

    def test_solvency_scope_real(self):
        corpus = DossierCorpus(REAL_REVIEWS_DIR)
        solvency = corpus.load_episodes_by_scope("solvency")
        if solvency:
            assert all(ep.review_scope == "solvency" for ep in solvency)
