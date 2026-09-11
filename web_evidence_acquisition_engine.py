import hashlib
import json
import os
import re
import time
from typing import Dict, Any, List, Optional, Tuple, Literal
from council_contracts import (
    ImmutableContract, DocumentConversionReceipt, WebEvidenceReceipt, ReceiptEnvelope
)

class LocalStructuredDocumentParser:
    """
    Local-first Document to Markdown Conversion Parser:
    - Converts CSV, JSON, HTML, XML, Markdown, and plain text files into clean structured Markdown tables and sections.
    - Operates locally with zero cloud reliance; computes cryptographic content digests.
    - Emits verifiable DocumentConversionReceipts.
    """

    def __init__(self, cas_storage_dir: Optional[str] = None):
        home_dir = os.environ.get("COUNCIL_STATE_DIR") or os.path.join(os.path.expanduser("~"), ".council_state")
        self.cas_dir = cas_storage_dir or os.path.join(home_dir, "cas", "documents")
        os.makedirs(self.cas_dir, exist_ok=True)

    def convert_file(self, file_path: str) -> Tuple[str, ReceiptEnvelope[DocumentConversionReceipt]]:
        """Reads and converts a local file into Markdown, persisting to CAS."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Source file not found: {file_path}")

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        file_sha = hashlib.sha256(raw_bytes).hexdigest()
        ext = os.path.splitext(file_path)[1].lower()

        markdown_text = ""
        mime_type = "text/plain"
        tables_count = 0
        headings_count = 0

        if ext in [".json", ".jsonl"]:
            mime_type = "application/json"
            try:
                data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                markdown_text = f"```json\n{json.dumps(data, indent=2)}\n```"
            except Exception:
                markdown_text = f"```text\n{raw_bytes.decode('utf-8', errors='replace')}\n```"
        elif ext in [".csv", ".tsv"]:
            mime_type = "text/csv"
            lines = raw_bytes.decode("utf-8", errors="replace").splitlines()
            if lines:
                headers = [h.strip() for h in lines[0].split("," if ext == ".csv" else "\t")]
                markdown_text = f"| {' | '.join(headers)} |\n| {' | '.join(['---'] * len(headers))} |\n"
                for row in lines[1:50]:
                    cols = [c.strip() for c in row.split("," if ext == ".csv" else "\t")]
                    markdown_text += f"| {' | '.join(cols)} |\n"
                tables_count = 1
        elif ext in [".html", ".htm"]:
            mime_type = "text/html"
            text_raw = raw_bytes.decode("utf-8", errors="replace")
            cleaned = re.sub(r'<script.*?</script>', '', text_raw, flags=re.DOTALL | re.IGNORECASE)
            cleaned = re.sub(r'<style.*?</style>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
            cleaned = re.sub(r'<h1.*?>(.*?)</h1>', r'\n# \1\n', cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r'<h2.*?>(.*?)</h2>', r'\n## \1\n', cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r'<h3.*?>(.*?)</h3>', r'\n### \1\n', cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r'<p.*?>(.*?)</p>', r'\n\1\n', cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r'<.*?>', '', cleaned)
            markdown_text = "\n".join([line.strip() for line in cleaned.splitlines() if line.strip()])
            headings_count = len(re.findall(r'^#+\s', markdown_text, flags=re.MULTILINE))
        elif ext in [".md", ".txt", ".py", ".ts", ".go", ".rs"]:
            mime_type = "text/markdown" if ext == ".md" else "text/plain"
            markdown_text = raw_bytes.decode("utf-8", errors="replace")
            headings_count = len(re.findall(r'^#+\s', markdown_text, flags=re.MULTILINE))
        else:
            mime_type = "application/octet-stream"
            markdown_text = f"# Document Artifact: `{os.path.basename(file_path)}`\n\nRaw size: {len(raw_bytes)} bytes (SHA-256: `{file_sha[:16]}`)."

        md_sha = hashlib.sha256(markdown_text.encode("utf-8")).hexdigest()

        # Save markdown and raw artifact to CAS
        cas_file = os.path.join(self.cas_dir, f"doc_{md_sha[:16]}.md")
        with open(cas_file, "w", encoding="utf-8") as f:
            f.write(markdown_text)

        cas_raw_file = os.path.join(self.cas_dir, f"raw_{file_sha[:16]}.bin")
        with open(cas_raw_file, "wb") as f:
            f.write(raw_bytes)

        receipt = DocumentConversionReceipt(
            source_file_path=os.path.abspath(file_path),
            source_mime_type=mime_type,
            source_file_sha256=file_sha,
            converter_engine="STRUCTURED_PARSER",
            extracted_markdown_sha256=md_sha,
            extracted_char_count=len(markdown_text),
            extracted_headings_count=headings_count,
            extracted_tables_count=tables_count,
            conversion_timestamp=time.time()
        )

        return markdown_text, ReceiptEnvelope.seal(receipt)

# Alias for backwards compatibility with tests
MarkItDownAdapter = LocalStructuredDocumentParser


class WebEvidenceAcquisitionEngine:
    """
    Normalized Web Evidence Acquisition Engine:
    - Ingests public web pages and DOM trees into structured Markdown.
    - Caches both raw bytes and Markdown artifacts in content-addressable storage for full truncation recovery.
    - Enforces privacy tier invariants (e.g. FIRECRAWL_API strictly requires PUBLIC_SAFE).
    - Emits verifiable WebEvidenceReceipts with byte hashes and privacy classifications.
    """

    def __init__(self, cas_storage_dir: Optional[str] = None):
        home_dir = os.environ.get("COUNCIL_STATE_DIR") or os.path.join(os.path.expanduser("~"), ".council_state")
        self.cas_dir = cas_storage_dir or os.path.join(home_dir, "cas", "web_evidence")
        os.makedirs(self.cas_dir, exist_ok=True)

    def ingest_html_content(
        self,
        source_url: str,
        html_content: str,
        http_status: int = 200,
        fetch_mode: Literal["LOCAL_HTTP", "CRAWL4AI_DOM", "FIRECRAWL_API", "PROXIED_SCRAPLING"] = "LOCAL_HTTP",
        privacy_tier: Literal["PUBLIC_SAFE", "INTERNAL_NO_TRAIN_OK", "LOCAL_ONLY_REQUIRED"] = "PUBLIC_SAFE",
        max_chars: int = 50000
    ) -> Tuple[str, ReceiptEnvelope[WebEvidenceReceipt]]:
        """
        Converts raw HTML to structured Markdown, writes both raw and MD to CAS, and seals a WebEvidenceReceipt.
        """
        # Invariant: External third-party scrapers (Firecrawl) are strictly restricted to PUBLIC_SAFE
        if fetch_mode == "FIRECRAWL_API" and privacy_tier != "PUBLIC_SAFE":
            raise ValueError(
                f"Security Invariant Violation: fetch_mode 'FIRECRAWL_API' is strictly restricted to 'PUBLIC_SAFE' tier; "
                f"cannot be used for '{privacy_tier}' data."
            )

        raw_bytes = html_content.encode("utf-8")
        raw_sha = hashlib.sha256(raw_bytes).hexdigest()

        # HTML to Markdown conversion
        cleaned = re.sub(r'<script.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        cleaned = re.sub(r'<style.*?</style>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
        cleaned = re.sub(r'<h1.*?>(.*?)</h1>', r'\n# \1\n', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'<h2.*?>(.*?)</h2>', r'\n## \1\n', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'<h3.*?>(.*?)</h3>', r'\n### \1\n', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'<p.*?>(.*?)</p>', r'\n\1\n', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'<a.*?href=["\'](.*?)["\'].*?>(.*?)</a>', r'[\2](\1)', cleaned, flags=re.DOTALL | re.IGNORECASE)
        cleaned = re.sub(r'<.*?>', ' ', cleaned)

        lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
        full_md = f"# Evidence Ingested from: `{source_url}`\n\n" + "\n\n".join(lines)

        is_truncated = len(full_md) > max_chars
        if is_truncated:
            full_md = full_md[:max_chars] + f"\n\n[TRUNCATED: Content exceeded {max_chars} chars; full raw artifact stored in CAS.]"

        md_sha = hashlib.sha256(full_md.encode("utf-8")).hexdigest()

        # Write both raw and markdown to CAS to guarantee full recovery
        cas_md_path = os.path.join(self.cas_dir, f"web_{md_sha[:16]}.md")
        with open(cas_md_path, "w", encoding="utf-8") as f:
            f.write(full_md)

        cas_raw_path = os.path.join(self.cas_dir, f"raw_{raw_sha[:16]}.html")
        with open(cas_raw_path, "wb") as f:
            f.write(raw_bytes)

        receipt = WebEvidenceReceipt(
            source_url=source_url,
            final_url=source_url,
            fetch_mode=fetch_mode,
            http_status=http_status,
            raw_content_sha256=raw_sha,
            markdown_sha256=md_sha,
            screenshot_sha256=None,
            is_truncated=is_truncated,
            total_raw_bytes=len(raw_bytes),
            cas_artifact_path=cas_md_path,
            privacy_tier=privacy_tier,
            fetched_at=time.time()
        )

        return full_md, ReceiptEnvelope.seal(receipt)
