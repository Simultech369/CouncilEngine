import hashlib
import json
import time
from typing import Dict, List, Literal, Tuple

from council_contracts import ImmutableContract, ReceiptEnvelope
from rlvr_ruler_reward_engine import TrajectoryRewardReceipt


class RLVRDatasetExample(ImmutableContract):
    trajectory_id: str
    objective_id: str
    messages: List[Dict[str, str]]
    scalar_reward: float
    reward_mode: Literal["RLVR", "RULER_RELATIVE"]
    reward_receipt_payload_sha256: str
    system_prompt_sha256: str
    trajectory_sha256: str


class RLVRDatasetExportReceipt(ImmutableContract):
    dataset_format: Literal["JSONL_MESSAGES_REWARD"]
    examples_count: int
    accepted_count: int
    rejected_count: int
    source_reward_payload_sha256s: List[str]
    dataset_sha256: str
    min_reward_threshold: float
    exported_at: float


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class RLVRDatasetExporter:
    """
    Converts sealed trajectory reward receipts into JSONL examples for GRPO/RLVR fine-tuning jobs.
    It exports only already-scored trajectories and never infers rewards from raw text.
    """

    def export_jsonl(
        self,
        reward_receipt_envs: List[ReceiptEnvelope[TrajectoryRewardReceipt]],
        messages_by_trajectory_id: Dict[str, List[Dict[str, str]]],
        min_reward_threshold: float = 0.8
    ) -> Tuple[str, ReceiptEnvelope[RLVRDatasetExportReceipt]]:
        if min_reward_threshold < 0.0 or min_reward_threshold > 1.0:
            raise ValueError("min_reward_threshold must be within [0.0, 1.0]")

        examples: List[RLVRDatasetExample] = []
        source_reward_shas: List[str] = []
        rejected_count = 0

        for env in sorted(reward_receipt_envs, key=lambda item: item.payload.trajectory_id):
            reward = env.payload
            source_reward_shas.append(env.payload_sha256)
            messages = messages_by_trajectory_id.get(reward.trajectory_id)
            if not messages or reward.scalar_reward < min_reward_threshold:
                rejected_count += 1
                continue

            examples.append(RLVRDatasetExample(
                trajectory_id=reward.trajectory_id,
                objective_id=reward.objective_id,
                messages=messages,
                scalar_reward=reward.scalar_reward,
                reward_mode=reward.reward_mode,
                reward_receipt_payload_sha256=env.payload_sha256,
                system_prompt_sha256=reward.system_prompt_sha256,
                trajectory_sha256=reward.trajectory_sha256
            ))

        lines = [
            json.dumps({
                "messages": example.messages,
                "reward": example.scalar_reward,
                "metadata": {
                    "trajectory_id": example.trajectory_id,
                    "objective_id": example.objective_id,
                    "reward_mode": example.reward_mode,
                    "reward_receipt_payload_sha256": example.reward_receipt_payload_sha256,
                    "system_prompt_sha256": example.system_prompt_sha256,
                    "trajectory_sha256": example.trajectory_sha256
                }
            }, sort_keys=True, separators=(",", ":"))
            for example in examples
        ]
        jsonl_text = "\n".join(lines)
        if jsonl_text:
            jsonl_text += "\n"

        receipt = RLVRDatasetExportReceipt(
            dataset_format="JSONL_MESSAGES_REWARD",
            examples_count=len(reward_receipt_envs),
            accepted_count=len(examples),
            rejected_count=rejected_count,
            source_reward_payload_sha256s=sorted(source_reward_shas),
            dataset_sha256=_sha256_text(jsonl_text),
            min_reward_threshold=min_reward_threshold,
            exported_at=time.time()
        )
        return jsonl_text, ReceiptEnvelope.seal(receipt)
