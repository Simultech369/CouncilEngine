import os
import shutil
import tempfile
import unittest
from web_evidence_acquisition_engine import LocalStructuredDocumentParser, MarkItDownAdapter, WebEvidenceAcquisitionEngine
from council_contracts import DocumentConversionReceipt, WebEvidenceReceipt

class TestWebEvidenceAcquisitionEngine(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.doc_adapter = LocalStructuredDocumentParser(cas_storage_dir=os.path.join(self.test_dir, "docs"))
        self.web_engine = WebEvidenceAcquisitionEngine(cas_storage_dir=os.path.join(self.test_dir, "web"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_convert_csv_and_json_documents(self):
        # 1. Test CSV
        csv_file = os.path.join(self.test_dir, "sample.csv")
        with open(csv_file, "w", encoding="utf-8") as f:
            f.write("id,name,score\n1,alice,95\n2,bob,88\n")

        md_csv, rec_csv_env = self.doc_adapter.convert_file(csv_file)
        self.assertIn("| id | name | score |", md_csv)
        self.assertIn("| 1 | alice | 95 |", md_csv)
        self.assertIsInstance(rec_csv_env.payload, DocumentConversionReceipt)
        self.assertEqual(rec_csv_env.payload.source_mime_type, "text/csv")
        self.assertEqual(rec_csv_env.payload.extracted_tables_count, 1)

        # 2. Test JSON
        json_file = os.path.join(self.test_dir, "sample.json")
        with open(json_file, "w", encoding="utf-8") as f:
            f.write('{"status": "ok", "count": 42}')

        md_json, rec_json_env = self.doc_adapter.convert_file(json_file)
        self.assertIn("```json", md_json)
        self.assertIn('"count": 42', md_json)
        self.assertEqual(rec_json_env.payload.source_mime_type, "application/json")

    def test_ingest_html_web_evidence(self):
        sample_html = """
        <html>
            <head><title>Test Page</title><style>.hidden{display:none}</style></head>
            <body>
                <h1>API Security Policy</h1>
                <p>All endpoints must require <b>cryptographic HMAC signatures</b>.</p>
                <a href="https://example.com/docs">Documentation</a>
                <script>alert('xss');</script>
            </body>
        </html>
        """

        md, rec_env = self.web_engine.ingest_html_content(
            source_url="https://api.internal/policy",
            html_content=sample_html,
            http_status=200,
            fetch_mode="LOCAL_HTTP",
            privacy_tier="PUBLIC_SAFE"
        )

        self.assertIn("# API Security Policy", md)
        self.assertIn("cryptographic HMAC signatures", md)
        self.assertIn("[Documentation](https://example.com/docs)", md)
        self.assertNotIn("<script>", md)
        self.assertNotIn("alert('xss')", md)

        receipt = rec_env.payload
        self.assertIsInstance(receipt, WebEvidenceReceipt)
        self.assertEqual(receipt.source_url, "https://api.internal/policy")
        self.assertEqual(receipt.http_status, 200)
        self.assertFalse(receipt.is_truncated)
        self.assertTrue(os.path.exists(receipt.cas_artifact_path))

    def test_firecrawl_privacy_tier_guard(self):
        sample_html = "<html><body><h1>Private Data</h1></body></html>"

        # FIRECRAWL_API paired with LOCAL_ONLY_REQUIRED must fail
        with self.assertRaises(ValueError):
            self.web_engine.ingest_html_content(
                source_url="https://internal.vault/data",
                html_content=sample_html,
                fetch_mode="FIRECRAWL_API",
                privacy_tier="LOCAL_ONLY_REQUIRED"
            )

        # FIRECRAWL_API paired with PUBLIC_SAFE must pass
        _, rec_env = self.web_engine.ingest_html_content(
            source_url="https://public.docs/guide",
            html_content=sample_html,
            fetch_mode="FIRECRAWL_API",
            privacy_tier="PUBLIC_SAFE"
        )
        self.assertEqual(rec_env.payload.privacy_tier, "PUBLIC_SAFE")

if __name__ == "__main__":
    unittest.main()
