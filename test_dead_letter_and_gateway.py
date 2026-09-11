import shutil
import tempfile
import unittest
from dead_letter_queue import DeadLetterQueue
from model_gateway import TokenBucketRateLimiter, CircuitBreaker

class TestDeadLetterAndGateway(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.dlq = DeadLetterQueue(storage_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_dlq_recording_and_taxonomy(self):
        self.dlq.record_failure(
            model_slug="qwen2.5-coder:7b",
            failure_category="SCHEMA_VIOLATION",
            raw_prompt="Review this patch",
            error_message="Missing 'decision' field",
            raw_response="{'status': 'ok'}"
        )
        self.dlq.record_failure(
            model_slug="deepseek-r1:7b",
            failure_category="TIMEOUT",
            raw_prompt="Analyze vulnerability",
            error_message="Connection timed out after 60s"
        )

        records = self.dlq.list_dead_letters()
        self.assertEqual(len(records), 2)

        taxonomy = self.dlq.get_failure_taxonomy_summary()
        self.assertEqual(taxonomy.get("SCHEMA_VIOLATION"), 1)
        self.assertEqual(taxonomy.get("TIMEOUT"), 1)

    def test_token_bucket_rate_limiter(self):
        limiter = TokenBucketRateLimiter(requests_per_minute=60, burst_limit=2)
        self.assertTrue(limiter.acquire())
        self.assertTrue(limiter.acquire())
        # Burst capacity exhausted
        self.assertFalse(limiter.acquire())

    def test_circuit_breaker_tripping(self):
        breaker = CircuitBreaker(failure_threshold=3, reset_timeout_sec=0.5)
        self.assertTrue(breaker.can_attempt())
        
        breaker.record_failure()
        self.assertEqual(breaker.state, "CLOSED")
        breaker.record_failure()
        self.assertEqual(breaker.state, "CLOSED")
        breaker.record_failure()
        # Threshold reached -> OPEN
        self.assertEqual(breaker.state, "OPEN")
        self.assertFalse(breaker.can_attempt())

    def test_model_gateway_protocol_adapters(self):
        from model_gateway import ModelGateway
        gateway = ModelGateway(dlq=self.dlq)

        # 1. SiliconFlow / OpenAI hosted route adapter
        target_url, headers, payload, proto = gateway._format_request(
            route_url="https://api.siliconflow.cn/v1/chat/completions",
            provider="siliconflow",
            model_slug="Qwen/Qwen2.5-Coder-32B-Instruct",
            prompt_text="Audit this patch for security"
        )
        self.assertEqual(target_url, "https://api.siliconflow.cn/v1/chat/completions")
        self.assertEqual(proto, "openai")
        self.assertIn("messages", payload)
        self.assertEqual(payload["messages"][0]["content"], "Audit this patch for security")
        self.assertEqual(payload["response_format"], {"type": "json_object"})

        mock_openai_resp = {
            "choices": [{"message": {"content": '{"decision": "approve"}'}}]
        }
        extracted_openai = gateway._extract_response_text(mock_openai_resp, proto)
        self.assertEqual(extracted_openai, '{"decision": "approve"}')

        # 2. Ollama local generate adapter
        target_url_ol, headers_ol, payload_ol, proto_ol = gateway._format_request(
            route_url="http://127.0.0.1:11434",
            provider="ollama_local",
            model_slug="qwen2.5-coder:7b",
            prompt_text="Audit this patch"
        )
        self.assertEqual(target_url_ol, "http://127.0.0.1:11434/api/generate")
        self.assertEqual(proto_ol, "ollama")
        self.assertIn("prompt", payload_ol)
        self.assertEqual(payload_ol["format"], "json")

        mock_ollama_resp = {"response": '{"decision": "reject"}'}
        extracted_ol = gateway._extract_response_text(mock_ollama_resp, proto_ol)
        self.assertEqual(extracted_ol, '{"decision": "reject"}')

if __name__ == "__main__":
    unittest.main()
