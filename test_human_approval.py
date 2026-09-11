import time
import unittest

from council_contracts import HumanApprovalReceipt, ReceiptEnvelope
from human_approval import CompositeApprovalAuthenticator, Ed25519ApprovalAuthenticator, HMACApprovalAuthenticator


class TestHumanApprovalAuthenticators(unittest.TestCase):

    def setUp(self):
        self.subject_sha = "abc123_subject"
        self.private_key = "01" * 32
        self.public_key = Ed25519ApprovalAuthenticator.derive_public_key(self.private_key)
        self.authenticator = Ed25519ApprovalAuthenticator({"key_operator_ed25519": self.public_key})

    def test_ed25519_signed_approval_authenticates_with_public_key_store(self):
        approval_env = Ed25519ApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=self.subject_sha,
            approver_identity="alice_security_lead",
            approver_key_id="key_operator_ed25519",
            private_key=self.private_key,
            validity_sec=3600
        )

        self.assertTrue(self.authenticator.authenticate_approval(approval_env, self.subject_sha))
        self.assertEqual(approval_env.payload.signature_algorithm, "ED25519")

    def test_ed25519_rejects_wrong_subject_binding(self):
        approval_env = Ed25519ApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=self.subject_sha,
            approver_identity="alice_security_lead",
            approver_key_id="key_operator_ed25519",
            private_key=self.private_key,
            validity_sec=3600
        )

        self.assertFalse(self.authenticator.authenticate_approval(approval_env, "other_subject"))

    def test_ed25519_rejects_wrong_public_key(self):
        approval_env = Ed25519ApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=self.subject_sha,
            approver_identity="alice_security_lead",
            approver_key_id="key_operator_ed25519",
            private_key=self.private_key,
            validity_sec=3600
        )
        wrong_public_key = Ed25519ApprovalAuthenticator.derive_public_key("02" * 32)
        wrong_authenticator = Ed25519ApprovalAuthenticator({"key_operator_ed25519": wrong_public_key})

        self.assertFalse(wrong_authenticator.authenticate_approval(approval_env, self.subject_sha))

    def test_ed25519_rejects_unknown_key_id(self):
        approval_env = Ed25519ApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=self.subject_sha,
            approver_identity="alice_security_lead",
            approver_key_id="missing_ed25519_key",
            private_key=self.private_key,
            validity_sec=3600
        )

        self.assertFalse(self.authenticator.authenticate_approval(approval_env, self.subject_sha))

    def test_ed25519_rejects_tampered_signed_receipt_body(self):
        approval_env = Ed25519ApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=self.subject_sha,
            approver_identity="alice_security_lead",
            approver_key_id="key_operator_ed25519",
            private_key=self.private_key,
            validity_sec=3600
        )
        tampered_payload = approval_env.payload.model_copy(update={"approver_identity": "mallory"})
        tampered_env = ReceiptEnvelope.seal(tampered_payload)

        self.assertFalse(self.authenticator.authenticate_approval(tampered_env, self.subject_sha))

    def test_ed25519_rejects_expired_approval(self):
        approval_env = Ed25519ApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=self.subject_sha,
            approver_identity="alice_security_lead",
            approver_key_id="key_operator_ed25519",
            private_key=self.private_key,
            validity_sec=-1
        )

        self.assertFalse(self.authenticator.authenticate_approval(approval_env, self.subject_sha))

    def test_algorithm_pinning_prevents_hmac_ed25519_confusion(self):
        hmac_env = HMACApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=self.subject_sha,
            approver_identity="alice_security_lead",
            approver_key_id="key_operator_ed25519",
            secret_key="shared-secret",
            validity_sec=3600
        )
        forged_payload = HumanApprovalReceipt(
            subject_type=hmac_env.payload.subject_type,
            subject_payload_sha256=hmac_env.payload.subject_payload_sha256,
            approver_identity=hmac_env.payload.approver_identity,
            approver_key_id=hmac_env.payload.approver_key_id,
            signature_algorithm="ED25519",
            detached_signature=hmac_env.payload.detached_signature,
            issued_at=hmac_env.payload.issued_at,
            expires_at=hmac_env.payload.expires_at
        )

        self.assertFalse(self.authenticator.authenticate_approval(ReceiptEnvelope.seal(forged_payload), self.subject_sha))

    def test_composite_authenticator_routes_hmac_and_ed25519_by_algorithm(self):
        hmac_authenticator = HMACApprovalAuthenticator({"key_operator_hmac": "shared-secret"})
        ed25519_authenticator = Ed25519ApprovalAuthenticator({"key_operator_ed25519": self.public_key})
        composite = CompositeApprovalAuthenticator({
            "HMAC_SHA256": hmac_authenticator,
            "ED25519": ed25519_authenticator
        })
        hmac_env = HMACApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=self.subject_sha,
            approver_identity="alice_security_lead",
            approver_key_id="key_operator_hmac",
            secret_key="shared-secret",
            validity_sec=3600
        )
        ed25519_env = Ed25519ApprovalAuthenticator.create_signed_approval(
            subject_type="PATCH_APPLY",
            subject_payload_sha256=self.subject_sha,
            approver_identity="alice_security_lead",
            approver_key_id="key_operator_ed25519",
            private_key=self.private_key,
            validity_sec=3600
        )

        self.assertTrue(composite.authenticate_approval(hmac_env, self.subject_sha))
        self.assertTrue(composite.authenticate_approval(ed25519_env, self.subject_sha))
        self.assertFalse(CompositeApprovalAuthenticator({"HMAC_SHA256": hmac_authenticator}).authenticate_approval(ed25519_env, self.subject_sha))


if __name__ == "__main__":
    unittest.main()
