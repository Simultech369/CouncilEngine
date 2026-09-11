import unittest
from distributed_merkle_state_sync import DistributedMerkleStateSync, MerkleDAGNode, MerkleSyncReceipt

class TestDistributedMerkleStateSync(unittest.TestCase):

    def setUp(self):
        self.node_a = DistributedMerkleStateSync(peer_id="node_us_east")
        self.node_b = DistributedMerkleStateSync(peer_id="node_eu_west")

    def test_insert_receipt_and_cid(self):
        node = self.node_a.insert_receipt(
            epoch_index=1,
            payload_type="ApplyAuthorizationReceipt",
            author_id="claude_leader",
            payload_sha256="abc123payloadsha"
        )
        self.assertIsInstance(node, MerkleDAGNode)
        self.assertTrue(node.cid.startswith("cid_0x12_"))
        self.assertEqual(node.epoch_index, 1)
        self.assertEqual(node.sequence_number, 1)

    def test_peer_synchronization_convergence(self):
        # Node A creates 2 receipts
        r1 = self.node_a.insert_receipt(1, "ApplyAuthorizationReceipt", "author_1", "sha_1")
        r2 = self.node_a.insert_receipt(1, "ApplyAuthorizationReceipt", "author_2", "sha_2")

        # Node B creates 1 distinct receipt
        r3 = self.node_b.insert_receipt(1, "ApplyAuthorizationReceipt", "author_3", "sha_3")

        # Sync Node A with Node B's state
        receipt = self.node_a.synchronize_with_peer("node_eu_west", self.node_b.dag_nodes)

        self.assertIsInstance(receipt, MerkleSyncReceipt)
        self.assertEqual(receipt.synchronized_nodes_count, 1)  # Node A learned r3
        self.assertEqual(len(receipt.symmetric_diff_cids), 3)  # r1, r2, r3 were divergent
        self.assertTrue(receipt.sync_converged)
        self.assertIn(r3.cid, self.node_a.dag_nodes)
        self.assertEqual(len(self.node_a.dag_nodes), 3)

if __name__ == "__main__":
    unittest.main()
