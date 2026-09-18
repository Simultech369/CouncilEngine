"""
Dream-RSI Offline Replay Engine
================================
Inspired by Google/DeepMind's recursive self-improvement via offline replay
simulators. Replays historical review dossiers against prompt/policy variants
to evaluate prompt changes without live API spend.

Architecture:
  1. DossierCorpus: Scans reviews/ directory for historical JSON+Markdown
     dossier pairs and parses them into structured replay episodes.
  2. ReplayEpisode: A frozen record of a historical review run, containing
     the prompt used, the model response, metadata, and scoring signals.
  3. DreamRSIReplayEngine: Runs replay episodes against a new prompt variant,
     scores each with the RLVR reward engine, and emits a DreamReplayReport
     containing before/after scalar rewards and deltas.

Usage:
    engine = DreamRSIReplayEngine(reviews_dir="reviews/")
    report = engine.replay_with_variant(
        variant_name="v2.2-tighter-solvency-checks",
        new_prompt_text=open("reviews/prompts/grok-council-prompt.txt").read(),
        evaluator_fn=my_evaluator  # optional custom scorer
    )
    print(report.summary())

Integration points:
  - rlvr_ruler_reward_engine.CouncilRLVRRewardEngine for reward scoring
  - council_contracts.ReceiptEnvelope for sealed, immutable report envelopes
"""

import glob
import hashlib
import json
import os
import re
import time
from typing import Callable, Dict, List, Literal, Optional, Tuple

from council_contracts import ImmutableContract, ReceiptEnvelope


# ──────────────────────────────────────────────────────────────────
# 1. Data Structures
# ──────────────────────────────────────────────────────────────────

class ReplayEpisode(ImmutableContract):
    """A frozen record of a single historical review run."""
    episode_id: str
    source_file: str
    review_scope: str  # e.g. "solvency", "zk", "architecture", "whole_repo"
    model_slug: str
    original_prompt_sha256: str
    response_text: str
    response_sha256: str
    metadata: Dict[str, object]


class EpisodeReplayResult(ImmutableContract):
    """Result of replaying one episode against a new prompt variant."""
    episode_id: str
    variant_name: str
    original_prompt_sha256: str
    variant_prompt_sha256: str
    # Scoring signals: each evaluator emits 0.0-1.0 per dimension
    signal_scores: Dict[str, float]
    composite_score: float
    delta_vs_baseline: Optional[float]
    notes: str


class DreamReplayReport(ImmutableContract):
    """Aggregate report from replaying a corpus against a prompt variant."""
    variant_name: str
    variant_prompt_sha256: str
    baseline_mean_score: float
    variant_mean_score: float
    delta: float
    episode_count: int
    results: List[EpisodeReplayResult]
    emitted_at: float


# ──────────────────────────────────────────────────────────────────
# 2. Default Evaluators
# ──────────────────────────────────────────────────────────────────

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _default_structural_evaluator(
    episode: ReplayEpisode,
    prompt_text: str,
) -> Dict[str, float]:
    """
    Deterministic structural evaluator for review dossier quality.
    Scores based on presence of expected structural markers without
    requiring live model inference.

    Signals emitted (all 0.0 or 1.0):
      - has_findings: response contains at least one finding/vulnerability/issue
      - has_severity: response classifies findings by severity
      - has_line_refs: response references specific line numbers
      - has_recommendation: response provides actionable recommendations
      - no_hallucinated_files: response doesn't reference non-existent markers
      - has_scope_alignment: response addresses the declared review scope
    """
    response = episode.response_text.lower()

    # Finding presence
    finding_markers = [
        "vulnerability", "finding", "issue", "bug", "risk",
        "concern", "recommendation", "severity", "critical",
        "high", "medium", "low", "informational"
    ]
    has_findings = 1.0 if any(m in response for m in finding_markers) else 0.0

    # Severity classification
    severity_markers = ["critical", "high", "medium", "low", "informational"]
    has_severity = 1.0 if sum(1 for m in severity_markers if m in response) >= 2 else 0.0

    # Line references (e.g. "line 42", "L42", "line:42")
    has_line_refs = 1.0 if re.search(r'(?:line\s*[:# ]?\s*\d+|L\d+)', response, re.IGNORECASE) else 0.0

    # Actionable recommendations
    rec_markers = [
        "recommend", "should", "consider", "suggest",
        "fix", "remediat", "mitigat", "use instead"
    ]
    has_recommendation = 1.0 if any(m in response for m in rec_markers) else 0.0

    # Hallucination guard: phantom file references
    phantom_markers = [
        "contracts/drafts/",  # known phantom path (LRN-006)
        "secret_key.txt",
        "admin_password",
    ]
    no_hallucinated_files = 0.0 if any(m in response for m in phantom_markers) else 1.0

    # Scope alignment: does the response reference the declared review scope?
    scope_terms = {
        "solvency": ["solvency", "solvent", "debt", "epoch", "escrow", "surplus"],
        "zk": ["zero knowledge", "zk", "nullifier", "proof", "privacy", "snark"],
        "architecture": ["architecture", "module", "component", "layer", "design"],
        "whole_repo": ["repository", "codebase", "project", "overall"],
        "frontend": ["frontend", "dashboard", "ui", "component", "react"],
        "governance": ["governance", "vote", "proposal", "quorum", "council"],
    }
    scope_key = episode.review_scope.lower().replace("-", "_").replace(" ", "_")
    relevant_terms = scope_terms.get(scope_key, [])
    if relevant_terms:
        has_scope_alignment = 1.0 if any(t in response for t in relevant_terms) else 0.0
    else:
        # Unknown scope — give benefit of doubt
        has_scope_alignment = 0.5

    # PROMPT ALIGNMENT (Evaluating the actual prompt variant)
    prompt_lower = prompt_text.lower()
    
    # 1. Invariant Shields: Does the prompt enforce LRN-015 protections?
    shields = ["_startround", "updatecreditlimit", "registervoterwithsignature"]
    prompt_has_invariant_shields = 1.0 if sum(1 for s in shields if s in prompt_lower) >= 2 else 0.0

    # 2. Prompt Scope Alignment: Does the prompt explicitly declare the expected scope?
    prompt_declares_scope = 1.0 if (scope_key in prompt_lower or scope_key == "general" or not prompt_text) else 0.0

    return {
        "has_findings": has_findings,
        "has_severity": has_severity,
        "has_line_refs": has_line_refs,
        "has_recommendation": has_recommendation,
        "no_hallucinated_files": no_hallucinated_files,
        "has_scope_alignment": has_scope_alignment,
        "prompt_has_invariant_shields": prompt_has_invariant_shields,
        "prompt_declares_scope": prompt_declares_scope,
    }


# ──────────────────────────────────────────────────────────────────
# 3. Dossier Corpus Parser
# ──────────────────────────────────────────────────────────────────

class DossierCorpus:
    """
    Scans the reviews/ directory for historical review artifacts and
    parses them into ReplayEpisode objects suitable for offline replay.

    Supported formats:
      - JSON+Markdown pairs: multimodal_swarm_loop-*.json + .md
      - Standalone review files: *-review.md, *-review.txt
      - Router metadata files: *-router-metadata.json
    """

    def __init__(self, reviews_dir: str = "reviews/"):
        self.reviews_dir = os.path.abspath(reviews_dir)
        if not os.path.isdir(self.reviews_dir):
            if reviews_dir == "reviews/":
                pbm_dir = os.path.abspath(os.path.join(self.reviews_dir, "..", "PBMRebateTreasuryFinal", "reviews"))
                if os.path.isdir(pbm_dir):
                    self.reviews_dir = pbm_dir
                    return
                os.makedirs(self.reviews_dir, exist_ok=True)
                return
            raise FileNotFoundError(f"reviews directory not found: {self.reviews_dir}")

    def _extract_scope_from_filename(self, filename: str) -> str:
        """Extract review scope from filename conventions."""
        basename = os.path.splitext(filename)[0]
        # multimodal_swarm_loop-solvency.json -> solvency
        if "swarm_loop-" in basename:
            scope = basename.split("swarm_loop-", 1)[1]
            # Strip suffixes like -dryrun, -smoke
            scope = re.sub(r'-(dryrun|smoke|fast|small|quorum|timeout|execute|reconciliation).*$', '', scope)
            return scope or "general"
        # multimodal_swarm_disagreement_matrix-zk.json -> zk
        if "disagreement_matrix-" in basename:
            scope = basename.split("disagreement_matrix-", 1)[1]
            return scope or "general"
        # grok-council-review.txt -> council
        if "council" in basename:
            return "governance"
        if "solvency" in basename:
            return "solvency"
        if "zk" in basename or "zero_zk" in basename:
            return "zk"
        if "guardrail" in basename:
            return "governance"
        if "skeptic" in basename:
            return "governance"
        return "general"

    def _extract_model_slug(self, filename: str, metadata: Optional[Dict] = None) -> str:
        """Extract model slug from metadata or filename."""
        if metadata:
            for key in ["model_slug", "model", "model_name", "routed_model"]:
                if key in metadata:
                    return str(metadata[key])
        basename = os.path.splitext(filename)[0]
        # grok-council-review.txt -> grok
        if basename.startswith("grok"):
            return "grok"
        if "gemma" in basename:
            return "gemma"
        if "qwen" in basename:
            return "qwen_coder"
        if "deepseek" in basename:
            return "deepseek_reasoner"
        if "kimi" in basename:
            return "kimi_long_context"
        if "glm4" in basename:
            return "glm4"
        if "free_code" in basename:
            return "free_code"
        if "open_claude" in basename:
            return "open_claude"
        if "ollama" in basename:
            return "ollama_local"
        return "unknown"

    def load_episodes(self) -> List[ReplayEpisode]:
        """Load all parseable review artifacts into ReplayEpisode objects."""
        episodes: List[ReplayEpisode] = []

        # Pattern 1: JSON + Markdown dossier pairs
        json_files = glob.glob(os.path.join(self.reviews_dir, "multimodal_swarm_*.json"))
        for json_path in sorted(json_files):
            md_path = os.path.splitext(json_path)[0] + ".md"
            if not os.path.isfile(md_path):
                continue
            filename = os.path.basename(json_path)
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
                with open(md_path, "r", encoding="utf-8") as f:
                    response_text = f.read()
            except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                continue

            if not response_text.strip():
                continue

            episode_id = f"swarm-{os.path.splitext(filename)[0]}"
            scope = self._extract_scope_from_filename(filename)
            model_slug = self._extract_model_slug(filename, metadata if isinstance(metadata, dict) else None)

            episodes.append(ReplayEpisode(
                episode_id=episode_id,
                source_file=filename,
                review_scope=scope,
                model_slug=model_slug,
                original_prompt_sha256=_sha256(json.dumps(metadata, sort_keys=True) if isinstance(metadata, dict) else str(metadata)),
                response_text=response_text,
                response_sha256=_sha256(response_text),
                metadata=metadata if isinstance(metadata, dict) else {"raw": str(metadata)},
            ))

        # Pattern 2: Standalone review files (*-review.md, *-review.txt)
        review_patterns = [
            os.path.join(self.reviews_dir, "*-review.md"),
            os.path.join(self.reviews_dir, "*-review.txt"),
            os.path.join(self.reviews_dir, "*-packet-review.md"),
        ]
        for pattern in review_patterns:
            for review_path in sorted(glob.glob(pattern)):
                filename = os.path.basename(review_path)
                # Check for companion router metadata
                metadata_path = os.path.splitext(review_path)[0].replace("-review", "-packet-router-metadata")
                if not metadata_path.endswith(".json"):
                    metadata_path = os.path.splitext(metadata_path)[0] + ".json"

                metadata: Dict = {}
                if os.path.isfile(metadata_path):
                    try:
                        with open(metadata_path, "r", encoding="utf-8") as f:
                            metadata = json.load(f)
                    except (json.JSONDecodeError, OSError):
                        pass

                try:
                    with open(review_path, "r", encoding="utf-8") as f:
                        response_text = f.read()
                except (UnicodeDecodeError, OSError):
                    continue

                if not response_text.strip():
                    continue

                episode_id = f"review-{os.path.splitext(filename)[0]}"
                scope = self._extract_scope_from_filename(filename)
                model_slug = self._extract_model_slug(filename, metadata)

                episodes.append(ReplayEpisode(
                    episode_id=episode_id,
                    source_file=filename,
                    review_scope=scope,
                    model_slug=model_slug,
                    original_prompt_sha256=_sha256(json.dumps(metadata, sort_keys=True) if metadata else ""),
                    response_text=response_text,
                    response_sha256=_sha256(response_text),
                    metadata=metadata,
                ))

        return episodes

    def load_episodes_by_scope(self, scope: str) -> List[ReplayEpisode]:
        """Load episodes filtered to a specific review scope."""
        return [ep for ep in self.load_episodes() if ep.review_scope == scope]

    def load_episodes_by_model(self, model_slug: str) -> List[ReplayEpisode]:
        """Load episodes filtered to a specific model slug."""
        return [ep for ep in self.load_episodes() if ep.model_slug == model_slug]

    def load_from_trajectories(self, trajectories_json_path: str) -> List[ReplayEpisode]:
        """
        Loads execution traces from Dizzy golden_trajectories.json or other
        dizzy.golden_trajectories.v1 JSON files and converts them into ReplayEpisode objects.
        """
        abs_path = os.path.abspath(trajectories_json_path)
        if not os.path.isfile(abs_path):
            raise FileNotFoundError(f"Trajectory file not found: {abs_path}")

        with open(abs_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        episodes = []
        trajectories = data.get("trajectories", [])
        for traj in trajectories:
            traj_id = traj.get("id", "unknown_traj")
            description = traj.get("description", "")
            steps = traj.get("steps", [])
            outcome = traj.get("outcome", "unknown")

            formatted_steps = []
            for i, step in enumerate(steps):
                actor = step.get("actor", "agent")
                tool = step.get("tool", "")
                content = step.get("content", "")
                result = step.get("result", "")
                status = step.get("status", "ok")
                formatted_steps.append(
                    f"Step {i+1} [{actor}] status={status}"
                    + (f" tool={tool}" if tool else "")
                    + (f" content={content}" if content else "")
                    + (f" result={result}" if result else "")
                )
            trajectory_text = f"Trajectory {traj_id} ({description})\nOutcome: {outcome}\n" + "\n".join(formatted_steps)

            meta = {
                "trajectory_id": traj_id,
                "description": description,
                "step_count": len(steps),
                "outcome": outcome,
                "source_schema": data.get("schema", "dizzy.golden_trajectories.v1")
            }

            episodes.append(ReplayEpisode(
                episode_id=f"traj-{traj_id}",
                source_file=os.path.basename(abs_path),
                review_scope="trajectory_execution",
                model_slug="dizzy_runtime_agent",
                original_prompt_sha256=_sha256(description),
                response_text=trajectory_text,
                response_sha256=_sha256(trajectory_text),
                metadata=meta
            ))
        return episodes


# ──────────────────────────────────────────────────────────────────
# 4. Dream-RSI Replay Engine
# ──────────────────────────────────────────────────────────────────

EvaluatorFn = Callable[[ReplayEpisode, str], Dict[str, float]]


class DreamRSIReplayEngine:
    """
    Replays historical review dossiers against prompt/policy variants
    and scores them using deterministic evaluators to measure whether
    a prompt change improves review quality without live API spend.

    This is the Dream-RSI pattern: recursive self-improvement via
    offline replay simulators using historical evidence as ground truth.
    """

    def __init__(
        self,
        reviews_dir: str = "reviews/",
        evaluator_fn: Optional[EvaluatorFn] = None,
    ):
        self.corpus = DossierCorpus(reviews_dir)
        self.evaluator_fn = evaluator_fn or _default_structural_evaluator

    def _score_episode(
        self,
        episode: ReplayEpisode,
        prompt_text: str,
    ) -> Tuple[Dict[str, float], float]:
        """Score a single episode against a prompt variant."""
        signals = self.evaluator_fn(episode, prompt_text)
        if not signals:
            return {}, 0.0
        composite = round(sum(signals.values()) / len(signals), 6)
        return signals, composite

    def _compute_baseline_scores(
        self,
        episodes: List[ReplayEpisode],
        baseline_prompt: str,
    ) -> Dict[str, float]:
        """Compute baseline scores for each episode."""
        baselines: Dict[str, float] = {}
        for episode in episodes:
            _, composite = self._score_episode(episode, baseline_prompt)
            baselines[episode.episode_id] = composite
        return baselines

    def replay_with_variant(
        self,
        variant_name: str,
        new_prompt_text: str,
        baseline_prompt_text: str = "",
        scope_filter: Optional[str] = None,
        model_filter: Optional[str] = None,
        max_episodes: Optional[int] = None,
    ) -> ReceiptEnvelope[DreamReplayReport]:
        """
        Replay the dossier corpus against a new prompt variant and produce
        a sealed DreamReplayReport comparing variant vs baseline scores.

        Args:
            variant_name: Human-readable label for this variant (e.g. "v2.2-solvency-tighter")
            new_prompt_text: The new prompt text to evaluate
            baseline_prompt_text: The baseline prompt to compare against (if empty,
                                  uses the original prompt from each episode)
            scope_filter: Optional filter to limit replay to a specific review scope
            model_filter: Optional filter to limit replay to a specific model
            max_episodes: Optional cap on number of episodes to replay
        """
        # Load and filter episodes
        if scope_filter:
            episodes = self.corpus.load_episodes_by_scope(scope_filter)
        elif model_filter:
            episodes = self.corpus.load_episodes_by_model(model_filter)
        else:
            episodes = self.corpus.load_episodes()

        if max_episodes and len(episodes) > max_episodes:
            episodes = episodes[:max_episodes]

        if not episodes:
            raise ValueError(
                f"No replay episodes found "
                f"(scope={scope_filter}, model={model_filter}, dir={self.corpus.reviews_dir})"
            )

        variant_sha = _sha256(new_prompt_text)

        # Score each episode against both baseline and variant
        results: List[EpisodeReplayResult] = []
        baseline_scores: List[float] = []
        variant_scores: List[float] = []

        for episode in episodes:
            # Baseline: either explicit baseline prompt or "score the original response as-is"
            baseline_text = baseline_prompt_text or ""
            _, baseline_composite = self._score_episode(episode, baseline_text)
            baseline_scores.append(baseline_composite)

            # Variant
            signals, variant_composite = self._score_episode(episode, new_prompt_text)
            variant_scores.append(variant_composite)

            delta = round(variant_composite - baseline_composite, 6) if baseline_composite is not None else None

            results.append(EpisodeReplayResult(
                episode_id=episode.episode_id,
                variant_name=variant_name,
                original_prompt_sha256=episode.original_prompt_sha256,
                variant_prompt_sha256=variant_sha,
                signal_scores=signals,
                composite_score=variant_composite,
                delta_vs_baseline=delta,
                notes=f"scope={episode.review_scope}, model={episode.model_slug}",
            ))

        # Aggregate
        baseline_mean = round(sum(baseline_scores) / len(baseline_scores), 6)
        variant_mean = round(sum(variant_scores) / len(variant_scores), 6)

        report = DreamReplayReport(
            variant_name=variant_name,
            variant_prompt_sha256=variant_sha,
            baseline_mean_score=baseline_mean,
            variant_mean_score=variant_mean,
            delta=round(variant_mean - baseline_mean, 6),
            episode_count=len(episodes),
            results=results,
            emitted_at=time.time(),
        )

        return ReceiptEnvelope.seal(report)

    def replay_trajectories(
        self,
        trajectories_path: str,
        variant_name: str,
        new_prompt_text: str,
        baseline_prompt_text: str = "",
        evaluator_fn: Optional[EvaluatorFn] = None,
    ) -> ReceiptEnvelope[DreamReplayReport]:
        """
        Replays external multi-step trajectories (e.g. from Dizzy golden_trajectories.json)
        against a candidate prompt or policy variant.
        """
        episodes = self.corpus.load_from_trajectories(trajectories_path)
        eval_fn = evaluator_fn or self.evaluator_fn
        variant_sha = _sha256(new_prompt_text)

        baseline_scores = []
        variant_scores = []
        results = []

        for episode in episodes:
            base_signals = eval_fn(episode, baseline_prompt_text)
            base_composite = round(sum(base_signals.values()) / len(base_signals), 6) if base_signals else 0.0
            baseline_scores.append(base_composite)

            var_signals = eval_fn(episode, new_prompt_text)
            var_composite = round(sum(var_signals.values()) / len(var_signals), 6) if var_signals else 0.0
            variant_scores.append(var_composite)

            delta = round(var_composite - base_composite, 6)

            results.append(EpisodeReplayResult(
                episode_id=episode.episode_id,
                variant_name=variant_name,
                original_prompt_sha256=episode.original_prompt_sha256,
                variant_prompt_sha256=variant_sha,
                signal_scores=var_signals,
                composite_score=var_composite,
                delta_vs_baseline=delta,
                notes=f"trajectory={episode.metadata.get('trajectory_id')}, steps={episode.metadata.get('step_count')}",
            ))

        b_mean = round(sum(baseline_scores) / len(baseline_scores), 6) if baseline_scores else 0.0
        v_mean = round(sum(variant_scores) / len(variant_scores), 6) if variant_scores else 0.0

        report = DreamReplayReport(
            variant_name=variant_name,
            variant_prompt_sha256=variant_sha,
            baseline_mean_score=b_mean,
            variant_mean_score=v_mean,
            delta=round(v_mean - b_mean, 6),
            episode_count=len(episodes),
            results=results,
            emitted_at=time.time(),
        )
        return ReceiptEnvelope.seal(report)


# ──────────────────────────────────────────────────────────────────
# 5. CLI Entry Point
# ──────────────────────────────────────────────────────────────────

def main():
    """Quick self-test: load corpus and replay with default evaluator."""
    import argparse

    parser = argparse.ArgumentParser(description="Dream-RSI Offline Replay Engine")
    parser.add_argument(
        "--reviews-dir",
        default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "reviews"),
        help="Path to reviews/ directory"
    )
    parser.add_argument("--scope", default=None, help="Filter by review scope")
    parser.add_argument("--model", default=None, help="Filter by model slug")
    parser.add_argument("--max-episodes", type=int, default=None, help="Max episodes to replay")
    parser.add_argument("--variant-name", default="baseline-structural-check", help="Variant label")
    parser.add_argument("--prompt-file", default=None, help="Path to prompt variant file")

    args = parser.parse_args()

    # Resolve reviews directory
    reviews_dir = os.path.abspath(args.reviews_dir)

    # Load prompt variant
    if args.prompt_file and os.path.isfile(args.prompt_file):
        with open(args.prompt_file, "r", encoding="utf-8") as f:
            prompt_text = f.read()
    else:
        prompt_text = "default structural evaluator — no prompt variant loaded"

    engine = DreamRSIReplayEngine(reviews_dir=reviews_dir)
    envelope = engine.replay_with_variant(
        variant_name=args.variant_name,
        new_prompt_text=prompt_text,
        scope_filter=args.scope,
        model_filter=args.model,
        max_episodes=args.max_episodes,
    )

    report = envelope.payload
    print("=" * 60)
    print("DREAM-RSI OFFLINE REPLAY REPORT")
    print("=" * 60)
    print(f"  Variant: {report.variant_name}")
    print(f"  Prompt SHA256: {report.variant_prompt_sha256[:16]}...")
    print(f"  Episodes replayed: {report.episode_count}")
    print(f"  Baseline mean score: {report.baseline_mean_score}")
    print(f"  Variant mean score:  {report.variant_mean_score}")
    print(f"  Delta:               {'+' if report.delta >= 0 else ''}{report.delta}")
    print(f"  Envelope SHA256: {envelope.envelope_sha256[:16]}...")
    print("=" * 60)

    # Per-episode details
    for result in report.results:
        marker = "+" if (result.delta_vs_baseline or 0) > 0 else ("-" if (result.delta_vs_baseline or 0) < 0 else "=")
        print(f"  [{marker}] {result.episode_id}: {result.composite_score:.4f} (delta={result.delta_vs_baseline})")

    print(f"\nSealed receipt type: {envelope.receipt_type}")
    print(f"Contract version: {envelope.contract_version}")


if __name__ == "__main__":
    main()
