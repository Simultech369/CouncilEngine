import hashlib
import json
import os
import time
import uuid
from typing import Dict, Any, List, Optional
from council_contracts import DeadLetterRecord, ReceiptEnvelope

class DeadLetterQueue:
    """
    Durable Content-Addressed Storage (CAS) for failed agent actions,
    schema violations, timeouts, and rejected patches.
    Feeds directly into DSPy prompt self-healing and Failure Museum analytics.
    """

    def __init__(self, storage_dir: Optional[str] = None):
        state_dir = os.environ.get("COUNCIL_STATE_DIR") or os.path.expanduser("~/.council_state")
        self.storage_dir = storage_dir or os.path.join(state_dir, "dead_letters")
        os.makedirs(self.storage_dir, exist_ok=True)

    def record_failure(
        self,
        model_slug: str,
        failure_category: str,
        raw_prompt: str,
        error_message: str,
        raw_response: Optional[str] = None,
        retry_count: int = 0
    ) -> DeadLetterRecord:
        now = time.time()
        prompt_sha = hashlib.sha256(raw_prompt.encode("utf-8")).hexdigest()
        dl_id = f"dl_{uuid.uuid4().hex[:10]}"
        
        record = DeadLetterRecord(
            dead_letter_id=dl_id,
            source_model_slug=model_slug,
            failure_category=failure_category,
            raw_prompt_sha256=prompt_sha,
            raw_error_message=str(error_message),
            raw_response_snippet=raw_response[:500] if raw_response else None,
            retry_count=retry_count,
            quarantined_at=now
        )

        file_name = f"{dl_id}_{failure_category}.json"
        file_path = os.path.join(self.storage_dir, file_name)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(record.model_dump_json(indent=2))

        return record

    def list_dead_letters(self, category: Optional[str] = None) -> List[DeadLetterRecord]:
        records = []
        if not os.path.exists(self.storage_dir):
            return records

        for fname in os.listdir(self.storage_dir):
            if fname.endswith(".json"):
                fpath = os.path.join(self.storage_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        rec = DeadLetterRecord(**data)
                        if category is None or rec.failure_category == category:
                            records.append(rec)
                except Exception:
                    continue
        return records

    def get_failure_taxonomy_summary(self) -> Dict[str, int]:
        records = self.list_dead_letters()
        summary = {}
        for r in records:
            summary[r.failure_category] = summary.get(r.failure_category, 0) + 1
        return summary
