import json
import os
import hashlib
import subprocess
import time
import uuid
from typing import Dict, Any, List, Optional, Tuple
from council_contracts import (
    ImmutableContract,
    ReceiptEnvelope,
    ReviewHopCommandRecord,
    ReviewHopTraceReceipt,
)

class OTelSpanRecord(ImmutableContract):
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    kind: str  # INTERNAL, CLIENT, SERVER
    start_time_ns: int
    end_time_ns: int
    duration_ms: float
    status_code: str  # OK, ERROR, UNSET
    attributes: Dict[str, Any]
    events: List[Dict[str, Any]]

class CouncilTelemetryTracer:
    """
    Framework-agnostic OpenTelemetry (OTel) distributed tracer:
    - W3C TraceContext compliant trace/span ID generation.
    - Zero-dependency span recording for LLM invocations, sandbox runs, and council votes.
    - NDJSON/JSON span logging for observability dashboards.
    """

    def __init__(self, trace_storage_dir: Optional[str] = None):
        state_dir = os.environ.get("COUNCIL_STATE_DIR") or os.path.expanduser("~/.council_state")
        self.trace_storage_dir = trace_storage_dir or os.path.join(state_dir, "traces")
        os.makedirs(self.trace_storage_dir, exist_ok=True)
        self.active_spans: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _sha256_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @classmethod
    def _sha256_json(cls, value: Any) -> str:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return cls._sha256_text(payload)

    def generate_trace_id(self) -> str:
        return uuid.uuid4().hex

    def generate_span_id(self) -> str:
        return uuid.uuid4().hex[:16]

    def start_span(
        self,
        name: str,
        trace_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        kind: str = "INTERNAL",
        attributes: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, str]:
        """Starts a span and returns (trace_id, span_id)."""
        import re
        if not re.match(r"^[A-Za-z0-9_.-]+$", name):
            raise ValueError(f"Invalid span name '{name}'. Must match ^[A-Za-z0-9_.-]+$")
        if trace_id is not None and not re.match(r"^[0-9a-fA-F-]+$", trace_id):
            raise ValueError(f"Invalid trace_id '{trace_id}'.")
        if parent_span_id is not None and not re.match(r"^[0-9a-fA-F-]+$", parent_span_id):
            raise ValueError(f"Invalid parent_span_id '{parent_span_id}'.")

        t_id = trace_id or self.generate_trace_id()
        s_id = self.generate_span_id()
        start_ns = time.time_ns()

        self.active_spans[s_id] = {
            "trace_id": t_id,
            "span_id": s_id,
            "parent_span_id": parent_span_id,
            "name": name,
            "kind": kind,
            "start_time_ns": start_ns,
            "attributes": attributes or {},
            "events": []
        }
        return t_id, s_id

    def add_span_event(self, span_id: str, event_name: str, attributes: Optional[Dict[str, Any]] = None):
        if span_id in self.active_spans:
            self.active_spans[span_id]["events"].append({
                "name": event_name,
                "time_ns": time.time_ns(),
                "attributes": attributes or {}
            })

    def end_span(
        self,
        span_id: str,
        status_code: str = "OK",
        error_message: Optional[str] = None,
        additional_attributes: Optional[Dict[str, Any]] = None
    ) -> OTelSpanRecord:
        """Ends a span, writes to trace CAS storage, and returns OTelSpanRecord."""
        if span_id not in self.active_spans:
            raise KeyError(f"Span ID '{span_id}' not found in active spans")

        span_data = self.active_spans.pop(span_id)
        end_ns = time.time_ns()
        duration_ms = round((end_ns - span_data["start_time_ns"]) / 1_000_000.0, 3)

        attrs = span_data["attributes"]
        if additional_attributes:
            attrs.update(additional_attributes)
        if error_message:
            attrs["error.message"] = str(error_message)

        record = OTelSpanRecord(
            trace_id=span_data["trace_id"],
            span_id=span_data["span_id"],
            parent_span_id=span_data["parent_span_id"],
            name=span_data["name"],
            kind=span_data["kind"],
            start_time_ns=span_data["start_time_ns"],
            end_time_ns=end_ns,
            duration_ms=duration_ms,
            status_code=status_code,
            attributes=attrs,
            events=span_data["events"]
        )

        trace_file = os.path.join(self.trace_storage_dir, f"trace_{record.trace_id}.ndjson")
        with open(trace_file, "a", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")

        return record

    def list_spans_for_trace(self, trace_id: str) -> List[OTelSpanRecord]:
        import re
        if not re.match(r"^[0-9a-fA-F-]+$", trace_id):
            raise ValueError(f"Invalid trace_id '{trace_id}'.")
        trace_file = os.path.join(self.trace_storage_dir, f"trace_{trace_id}.ndjson")
        if not os.path.exists(trace_file):
            return []

        spans = []
        with open(trace_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    spans.append(OTelSpanRecord(**json.loads(line)))
        return spans

    def build_command_record(
        self,
        command_argv: List[str],
        executed: bool,
        exit_code: Optional[int] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        duration_sec: Optional[float] = None
    ) -> ReviewHopCommandRecord:
        if not command_argv:
            raise ValueError("command_argv cannot be empty")
        if not executed and any(value is not None for value in (exit_code, stdout, stderr, duration_sec)):
            raise ValueError("non-executed command records cannot include execution artifacts")
        if executed and exit_code is None:
            raise ValueError("executed command records must include exit_code")

        redacted_argv = []
        skip_next = False
        for i, arg in enumerate(command_argv):
            arg_str = str(arg)
            if skip_next:
                redacted_argv.append("[REDACTED]")
                skip_next = False
                continue
            if arg_str.lower() in ("--key", "-k", "--authorization", "authorization"):
                redacted_argv.append(arg_str)
                skip_next = True
            elif arg_str.lower().startswith("--key=") or arg_str.lower().startswith("-k=") or arg_str.lower().startswith("--authorization=") or arg_str.lower().startswith("authorization="):
                parts = arg_str.split("=", 1)
                redacted_argv.append(f"{parts[0]}=[REDACTED]")
            else:
                redacted_argv.append(arg_str)

        stdout_sha = self._sha256_text(stdout or "") if stdout is not None else None
        stderr_sha = self._sha256_text(stderr or "") if stderr is not None else None
        return ReviewHopCommandRecord(
            command_argv=redacted_argv,
            command_sha256=self._sha256_json(redacted_argv),
            executed=executed,
            exit_code=exit_code,
            stdout_sha256=stdout_sha,
            stderr_sha256=stderr_sha,
            duration_sec=duration_sec
        )

    @staticmethod
    def _parse_porcelain_z(stdout: bytes) -> List[str]:
        entries = [part for part in stdout.split(b"\0") if part]
        dirty_files: List[str] = []
        idx = 0
        while idx < len(entries):
            entry = entries[idx].decode("utf-8", errors="replace")
            status = entry[:2].ljust(2)
            path_part = entry[3:] if len(entry) > 3 else entry.strip()
            if path_part:
                dirty_files.append(path_part.replace("\\", "/"))
            if status[0] in {"R", "C"} or status[1] in {"R", "C"}:
                idx += 1
            idx += 1
        return sorted(dirty_files)

    def _run_git_text(self, root: str, args: List[str], timeout: int = 5) -> Tuple[bool, str]:
        try:
            completed = subprocess.run(
                ["git", "-C", root, *args],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout
            )
        except Exception:
            return False, ""
        if completed.returncode != 0:
            return False, ""
        return True, completed.stdout.strip()

    def _run_git_bytes(self, root: str, args: List[str], timeout: int = 5) -> Tuple[bool, bytes]:
        try:
            completed = subprocess.run(
                ["git", "-C", root, *args],
                check=False,
                capture_output=True,
                timeout=timeout
            )
        except Exception:
            return False, b""
        if completed.returncode != 0:
            return False, b""
        return True, completed.stdout

    def collect_toolchain_manifest_sha256(self, repo_root: Optional[str] = None) -> str:
        root = os.path.abspath(repo_root or os.getcwd())
        manifest: Dict[str, Any] = {}
        for label, argv in {
            "python": ["python", "--version"],
            "node": ["node", "--version"],
            "npm": ["npm.cmd", "--version"] if os.name == "nt" else ["npm", "--version"],
            "npx": ["npx.cmd", "--version"] if os.name == "nt" else ["npx", "--version"],
            "git": ["git", "--version"],
        }.items():
            try:
                completed = subprocess.run(
                    argv,
                    cwd=root,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                manifest[label] = {
                    "argv_sha256": self._sha256_json(argv),
                    "return_code": completed.returncode,
                    "stdout_sha256": self._sha256_text(completed.stdout or ""),
                    "stderr_sha256": self._sha256_text(completed.stderr or ""),
                }
            except Exception as err:
                manifest[label] = {
                    "argv_sha256": self._sha256_json(argv),
                    "error_type": err.__class__.__name__,
                }
        return self._sha256_json(manifest)

    def collect_git_state(self, repo_root: Optional[str] = None) -> Dict[str, Any]:
        root = os.path.abspath(repo_root or os.getcwd())
        head_ok, head = self._run_git_text(root, ["rev-parse", "HEAD"])
        branch_ok, branch = self._run_git_text(root, ["branch", "--show-current"])
        status_ok, status_bytes = self._run_git_bytes(root, ["status", "--porcelain=v1", "-z"])
        diff_ok, unstaged_diff = self._run_git_bytes(root, ["diff", "--binary"], timeout=15)
        cached_ok, staged_diff = self._run_git_bytes(root, ["diff", "--cached", "--binary"], timeout=15)

        observed = head_ok and status_ok and diff_ok and cached_ok
        if observed:
            dirty_files = self._parse_porcelain_z(status_bytes)
            reviewed_content_sha = self._sha256_json({
                "head": head,
                "dirty_files": dirty_files,
                "staged_diff_sha256": hashlib.sha256(staged_diff).hexdigest(),
                "unstaged_diff_sha256": hashlib.sha256(unstaged_diff).hexdigest(),
            })
            return {
                "git_head_commit": head,
                "git_branch": branch if branch_ok and branch else "DETACHED_OR_UNKNOWN",
                "git_observation_status": "OBSERVED",
                "working_tree_dirty": bool(dirty_files),
                "dirty_files": dirty_files,
                "reviewed_content_sha256": reviewed_content_sha,
            }

        return {
            "git_head_commit": head if head_ok and head else "UNKNOWN",
            "git_branch": branch if branch_ok and branch else "DETACHED_OR_UNKNOWN",
            "git_observation_status": "UNAVAILABLE",
            "working_tree_dirty": True,
            "dirty_files": ["UNKNOWN_GIT_STATUS"],
            "reviewed_content_sha256": self._sha256_json({
                "git_observation_status": "UNAVAILABLE",
                "head": head if head_ok and head else "UNKNOWN",
                "status_observed": status_ok,
                "diff_observed": diff_ok,
                "cached_diff_observed": cached_ok,
            }),
        }

    def seal_review_hop_trace(
        self,
        source_agent_id: str,
        target_agent_id: str,
        hop_kind: str,
        input_payload: Any,
        output_payload: Any,
        repo_root: Optional[str] = None,
        command_records: Optional[List[ReviewHopCommandRecord]] = None,
        isolation_mode: str = "READ_ONLY_NO_EXECUTION",
        network_isolated: bool = False,
        proof_boundary: str = (
            "Provenance receipt only. Hashes record observed local inputs, outputs, commands, "
            "and git state; they do not prove audit completeness, production execution, or "
            "sandbox isolation beyond the stated isolation_mode."
        ),
        trace_id: Optional[str] = None,
        hop_id: Optional[str] = None,
    ) -> ReceiptEnvelope[ReviewHopTraceReceipt]:
        if isolation_mode == "LOCAL_SUBPROCESS_MOCK" and network_isolated:
            raise ValueError("LOCAL_SUBPROCESS_MOCK cannot claim network isolation")
        if isolation_mode == "DOCKER_CONTAINER_ENFORCED":
            raise ValueError("DOCKER_CONTAINER_ENFORCED requires a verified sandbox receipt and is not emitted by this tracer")
        if isolation_mode == "READ_ONLY_NO_EXECUTION":
            executed = [cmd for cmd in (command_records or []) if cmd.executed]
            if executed:
                raise ValueError("READ_ONLY_NO_EXECUTION cannot include executed command records")

        git_state = self.collect_git_state(repo_root)
        commands = command_records or []
        command_manifest_sha = self._sha256_json([cmd.model_dump() for cmd in commands])
        toolchain_manifest_sha = self.collect_toolchain_manifest_sha256(repo_root)
        t_id = trace_id or self.generate_trace_id()
        _, span_id = self.start_span(
            name=f"council.review_hop.{hop_kind.lower()}",
            trace_id=t_id,
            kind="INTERNAL",
            attributes={
                "review.source_agent_id": source_agent_id,
                "review.target_agent_id": target_agent_id,
                "review.hop_kind": hop_kind,
                "git.head": git_state["git_head_commit"],
                "git.branch": git_state["git_branch"],
                "git.observation_status": git_state["git_observation_status"],
                "git.dirty": git_state["working_tree_dirty"],
                "git.reviewed_content_sha256": git_state["reviewed_content_sha256"],
                "sandbox.isolation_mode": isolation_mode,
                "sandbox.network_isolated": network_isolated,
            }
        )
        h_id = hop_id or span_id
        environment_hash = self._sha256_json({
            **git_state,
            "command_manifest_sha256": command_manifest_sha,
            "toolchain_manifest_sha256": toolchain_manifest_sha,
            "isolation_mode": isolation_mode,
            "network_isolated": network_isolated,
        })

        receipt = ReviewHopTraceReceipt(
            trace_id=t_id,
            hop_id=h_id,
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            hop_kind=hop_kind,
            git_head_commit=git_state["git_head_commit"],
            git_branch=git_state["git_branch"],
            git_observation_status=git_state["git_observation_status"],
            working_tree_dirty=git_state["working_tree_dirty"],
            dirty_files=git_state["dirty_files"],
            reviewed_content_sha256=git_state["reviewed_content_sha256"],
            toolchain_manifest_sha256=toolchain_manifest_sha,
            input_payload_sha256=self._sha256_json(input_payload),
            output_payload_sha256=self._sha256_json(output_payload),
            command_manifest_sha256=command_manifest_sha,
            commands=commands,
            isolation_mode=isolation_mode,
            network_isolated=network_isolated,
            execution_environment_hash_sha256=environment_hash,
            provenance_only=True,
            remote_execution_permitted=False,
            production_execution_claimed=False,
            audit_replacement_claimed=False,
            proof_boundary=proof_boundary,
            traced_at=time.time()
        )
        env = ReceiptEnvelope.seal(receipt)
        self.end_span(
            span_id,
            status_code="OK",
            additional_attributes={
                "receipt.type": env.receipt_type,
                "receipt.payload_sha256": env.payload_sha256,
                "receipt.envelope_sha256": env.envelope_sha256,
            }
        )
        return env
