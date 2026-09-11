import hashlib
import textwrap
import time
from typing import List, Tuple

from council_contracts import ImmutableContract, ReceiptEnvelope


class StateMRunbookExportReceipt(ImmutableContract):
    runbook_name: str
    runbook_sha256: str
    initial_state: str
    node_count: int
    edge_count: int
    verification_command: str
    lifecycle_hooked: bool
    exported_at: float


class StateMRunbookBridge:
    """
    Dependency-free StateM runbook exporter for Council long-horizon runs.
    The emitted YAML can be validated by StateM when that CLI is installed.
    """

    DEFAULT_TEST_COMMAND = 'python -B -m unittest discover -p "test_*.py"'
    REQUIRED_NODES = ["plan", "execute", "verify", "handoff"]
    REQUIRED_EDGES = [
        ("plan", "execute"),
        ("execute", "verify"),
        ("verify", "execute"),
        ("verify", "handoff")
    ]

    def export_council_runbook(
        self,
        runbook_name: str = "council-engine-implementation-loop",
        verification_command: str = DEFAULT_TEST_COMMAND
    ) -> Tuple[str, ReceiptEnvelope[StateMRunbookExportReceipt]]:
        runbook_text = textwrap.dedent(f"""
            name: {runbook_name}
            initial: plan

            nodes:
              plan:
                prompt: |
                  Read the objective, inspect the live repository state, and record exact verification steps.
                before_transfer:
                  type: checklist
                  items:
                    - Scope and constraints are recorded
                    - Verification steps are defined

              execute:
                prompt: |
                  Implement the scoped change using Council lifecycle hooks around real effects.
                before_transfer:
                  - type: checklist
                    items:
                      - File changes are limited to the current objective
                      - Hook receipts exist for real tool or sandbox effects

              verify:
                prompt: |
                  Run deterministic verification and repair any fixable failure before handoff.
                before_transfer:
                  - type: command
                    run: '{verification_command}'
                  - type: checklist
                    items:
                      - Relevant focused tests pass
                      - Full discovery suite pass state is known

              handoff:
                prompt: |
                  Summarize changed files, verification receipts, counts, and remaining risks.

            edges:
              - from: plan
                to: execute
                condition: The plan is ready and bounded.
              - from: execute
                to: verify
                condition: The implementation is ready for deterministic checks.
              - from: verify
                to: execute
                condition: Verification found a fixable gap.
              - from: verify
                to: handoff
                condition: Implementation and verification are complete.
            """).strip() + "\n"

        self.validate_runbook_text(runbook_text)
        runbook_sha = hashlib.sha256(runbook_text.encode("utf-8")).hexdigest()
        receipt = StateMRunbookExportReceipt(
            runbook_name=runbook_name,
            runbook_sha256=runbook_sha,
            initial_state="plan",
            node_count=len(self.REQUIRED_NODES),
            edge_count=len(self.REQUIRED_EDGES),
            verification_command=verification_command,
            lifecycle_hooked=True,
            exported_at=time.time()
        )
        return runbook_text, ReceiptEnvelope.seal(receipt)

    def validate_runbook_text(self, runbook_text: str) -> bool:
        missing: List[str] = []
        for token in ("name:", "initial: plan", "nodes:", "edges:", "before_transfer:"):
            if token not in runbook_text:
                missing.append(token)
        for node in self.REQUIRED_NODES:
            if f"  {node}:" not in runbook_text:
                missing.append(f"node:{node}")
        for source, target in self.REQUIRED_EDGES:
            if f"from: {source}" not in runbook_text or f"to: {target}" not in runbook_text:
                missing.append(f"edge:{source}->{target}")
        if missing:
            raise ValueError("StateM runbook missing required fields: " + ", ".join(missing))
        return True
