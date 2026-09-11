import unittest
from rag_evidence_engine import RAGEvidenceEngine
from council_contracts import EvidenceSelectionReceipt, CitationGroundingReceipt

class TestRAGEvidenceEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RAGEvidenceEngine()
        self.sample_code = """
def authenticate_user(username, password):
    # Line 2: start auth
    if not username or not password:
        return False
    user = db.find_user(username)
    if not user:
        return False
    # Line 8: verify hash
    return verify_hash(password, user.password_hash)

def logout_user(session_id):
    # Line 12: clear session
    db.clear_session(session_id)
    return True
"""

    def test_document_chunking(self):
        chunks = self.engine.chunk_document("src/auth.py", self.sample_code, chunk_size_lines=10, overlap_lines=2)
        self.assertGreater(len(chunks), 0)
        self.assertEqual(chunks[0].file_path, "src/auth.py")
        self.assertEqual(chunks[0].start_line, 1)

    def test_retrieve_and_rerank_selection(self):
        chunks_auth = self.engine.chunk_document("src/auth.py", self.sample_code)
        chunks_util = self.engine.chunk_document("src/utils.py", "def helper(): pass\n")
        all_chunks = chunks_auth + chunks_util

        evidence_env = self.engine.retrieve_and_rerank(
            query="authenticate_user password verification",
            packet_payload_sha="dummy_packet_sha_12345",
            candidate_chunks=all_chunks,
            top_k=2
        )
        self.assertIsInstance(evidence_env.payload, EvidenceSelectionReceipt)
        self.assertEqual(len(evidence_env.payload.selected_chunks), 2)
        # Reranked chunk for auth should have highest score
        self.assertEqual(evidence_env.payload.selected_chunks[0].file_path, "src/auth.py")

    def test_missing_context_detection(self):
        chunks = self.engine.chunk_document("src/auth.py", self.sample_code)

        evidence_env = self.engine.retrieve_and_rerank(
            query="find_user",
            packet_payload_sha="dummy_packet_sha",
            candidate_chunks=chunks,
            top_k=5,
            required_keywords=["db_connection.py"]
        )
        self.assertTrue(evidence_env.payload.missing_context_detected)
        self.assertIn("db_connection.py", evidence_env.payload.missing_context_files)

    def test_citation_grounding_verification(self):
        chunks = self.engine.chunk_document("src/auth.py", self.sample_code, chunk_size_lines=20)
        evidence_env = self.engine.retrieve_and_rerank(
            query="auth",
            packet_payload_sha="dummy_packet_sha",
            candidate_chunks=chunks,
            top_k=1
        )

        # 1. Grounded citation: cited lines (2, 8) fall within the chunk boundary (lines 1 to 16)
        grounded_env = self.engine.verify_citation_grounding(
            evidence_receipt_env=evidence_env,
            model_slug="qwen/qwen-3.8-coder",
            cited_lines=[2, 8],
            target_file="src/auth.py"
        )
        self.assertTrue(grounded_env.payload.grounding_verified)
        self.assertEqual(grounded_env.payload.unverified_claims_count, 0)

        # 2. Hallucinated line citation: line 999 does not exist in the selected chunk
        hallucinated_env = self.engine.verify_citation_grounding(
            evidence_receipt_env=evidence_env,
            model_slug="hallucinating-model",
            cited_lines=[999],
            target_file="src/auth.py"
        )
        self.assertFalse(hallucinated_env.payload.grounding_verified)
        self.assertEqual(hallucinated_env.payload.unverified_claims_count, 1)

if __name__ == "__main__":
    unittest.main()
