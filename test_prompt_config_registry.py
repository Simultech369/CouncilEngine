import unittest

from council_contracts import CONTRACT_VERSION, PromptConfigRegistryReceipt
from council_verifier import CouncilReceiptVerifier
from prompt_config_registry import (
    PromptConfigRegistry,
    normalize_system_prompt,
    sha256_text,
)


class PromptConfigRegistryTest(unittest.TestCase):
    def test_register_active_prompt_hashes_prompt_and_config_deterministically(self):
        registry_a = PromptConfigRegistry(registry_id="unit")
        registry_b = PromptConfigRegistry(registry_id="unit")
        provider_a = {"temperature": 0.2, "model": "qwen"}
        provider_b = {"model": "qwen", "temperature": 0.2}

        record_a = registry_a.register_prompt_version(
            prompt_id="council.vote",
            version="1.0.0",
            system_prompt="Vote only from cited evidence.",
            provider_parameters=provider_a,
            stage="ACTIVE",
            created_at=1.0,
        )
        record_b = registry_b.register_prompt_version(
            prompt_id="council.vote",
            version="1.0.0",
            system_prompt="Vote only from cited evidence.",
            provider_parameters=provider_b,
            stage="ACTIVE",
            created_at=1.0,
        )

        self.assertEqual(record_a.config_sha256, record_b.config_sha256)
        self.assertEqual(
            record_a.normalized_system_prompt_sha256,
            sha256_text("Vote only from cited evidence."),
        )

    def test_duplicate_prompt_version_is_rejected(self):
        registry = PromptConfigRegistry()
        registry.register_prompt_version(
            prompt_id="agent.patch",
            version="1",
            system_prompt="Create a minimal patch.",
        )

        with self.assertRaises(ValueError):
            registry.register_prompt_version(
                prompt_id="agent.patch",
                version="1",
                system_prompt="Create a different patch.",
            )

    def test_parent_chain_and_activation_deprecates_previous_active(self):
        registry = PromptConfigRegistry()
        first = registry.register_prompt_version(
            prompt_id="agent.patch",
            version="1",
            system_prompt="Create a minimal patch.",
            stage="ACTIVE",
            created_at=1.0,
        )
        second = registry.register_prompt_version(
            prompt_id="agent.patch",
            version="2",
            system_prompt="Create a minimal patch with receipts.",
            parent_version="1",
            stage="ACTIVE",
            created_at=2.0,
        )

        self.assertEqual(second.parent_version_sha256, first.compute_canonical_sha256())
        self.assertEqual(registry.get_version("agent.patch", "1").stage, "DEPRECATED")
        self.assertEqual(registry.get_active("agent.patch").version, "2")

    def test_rollback_restores_prior_active_without_deleting_history(self):
        registry = PromptConfigRegistry()
        registry.register_prompt_version(
            prompt_id="agent.patch",
            version="1",
            system_prompt="Create a minimal patch.",
            stage="ACTIVE",
        )
        registry.register_prompt_version(
            prompt_id="agent.patch",
            version="2",
            system_prompt="Create a minimal patch with receipts.",
            parent_version="1",
            stage="ACTIVE",
        )

        receipt = registry.rollback_prompt_version(prompt_id="agent.patch", target_version="1")

        self.assertEqual(registry.get_active("agent.patch").version, "1")
        self.assertEqual(registry.get_version("agent.patch", "2").stage, "DEPRECATED")
        self.assertEqual(len(registry.list_versions("agent.patch")), 2)
        self.assertEqual(receipt.contract_version, CONTRACT_VERSION)

    def test_export_registry_receipt_is_sealed_and_verifiable(self):
        registry = PromptConfigRegistry(registry_id="unit")
        record = registry.register_prompt_version(
            prompt_id="council.vote",
            version="1.0.0",
            system_prompt="Vote only from cited evidence.",
            stage="ACTIVE",
        )

        envelope = registry.export_registry_receipt(active_prompt_id="council.vote")

        self.assertEqual(envelope.receipt_type, "PromptConfigRegistryReceipt")
        self.assertEqual(
            envelope.payload.active_system_prompt_sha256,
            record.normalized_system_prompt_sha256,
        )
        CouncilReceiptVerifier.verify_envelope(envelope, PromptConfigRegistryReceipt)
        receipt = PromptConfigRegistryReceipt(**envelope.payload.model_dump())
        self.assertEqual(receipt.version_count, 1)

    def test_invalid_prompt_and_identifiers_are_rejected(self):
        registry = PromptConfigRegistry()

        with self.assertRaises(ValueError):
            registry.register_prompt_version(
                prompt_id="../unsafe",
                version="1",
                system_prompt="Prompt",
            )
        with self.assertRaises(ValueError):
            registry.register_prompt_version(
                prompt_id="safe",
                version="1",
                system_prompt="   ",
            )

    def test_prompt_normalization_ignores_line_endings_and_trailing_spaces(self):
        windows_text = "Line one.  \r\nLine two.\r\n"
        unix_text = "Line one.\nLine two."

        self.assertEqual(normalize_system_prompt(windows_text), unix_text)
        self.assertEqual(sha256_text(normalize_system_prompt(windows_text)), sha256_text(unix_text))


if __name__ == "__main__":
    unittest.main()
