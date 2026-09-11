import json
import time
import unittest
from p2p_gossip_transport import P2PGossipTransportNode, GossipMessage, SignedGossipEnvelope, GossipSecurityError
from distributed_merkle_state_sync import MerkleDAGNode, MerkleSyncReceipt

class TestP2PGossipTransport(unittest.TestCase):

    def setUp(self):
        self.node_a = P2PGossipTransportNode(peer_id="node_us_east", host="127.0.0.1", port=9211)
        self.node_b = P2PGossipTransportNode(peer_id="node_eu_west", host="127.0.0.1", port=9212)

    def tearDown(self):
        self.node_a.stop_listener()
        self.node_b.stop_listener()

    def _signed_nodes(self, port_a: int = 9221, port_b: int = 9222):
        private_a = "01" * 32
        private_b = "02" * 32
        public_a = P2PGossipTransportNode.derive_public_key(private_a)
        public_b = P2PGossipTransportNode.derive_public_key(private_b)
        signed_a = P2PGossipTransportNode(
            peer_id="node_us_east",
            host="127.0.0.1",
            port=port_a,
            private_key=private_a,
            trusted_peer_public_keys={"node_eu_west": public_b},
            require_signed_messages=True
        )
        signed_b = P2PGossipTransportNode(
            peer_id="node_eu_west",
            host="127.0.0.1",
            port=port_b,
            private_key=private_b,
            trusted_peer_public_keys={"node_us_east": public_a},
            require_signed_messages=True
        )
        return signed_a, signed_b

    def test_message_creation_and_handling(self):
        # Insert a receipt into node A
        node_node = self.node_a.sync_engine.insert_receipt(
            epoch_index=1,
            payload_type="SPEND_SETTLEMENT",
            author_id="node_us_east",
            payload_sha256="sha_east_01",
            parent_cids=[]
        )
        node_id = node_node.cid
        self.assertIn(node_id, self.node_a.sync_engine.dag_nodes)

        msg = self.node_a.create_announcement_message()
        self.assertIsInstance(msg, GossipMessage)
        self.assertEqual(msg.sender_peer_id, "node_us_east")
        self.assertEqual(len(msg.payload_nodes), 1)

        # Handle inbound message on node B
        ack = self.node_b.handle_inbound_message(msg.model_dump_json().encode("utf-8"))
        self.assertEqual(ack.message_type, "ACK")
        self.assertEqual(ack.sender_peer_id, "node_eu_west")
        self.assertIn(node_id, self.node_b.sync_engine.dag_nodes)

    def test_live_socket_gossip_sync(self):
        # Insert distinct receipts into both nodes
        node_a_rec = self.node_a.sync_engine.insert_receipt(
            epoch_index=1,
            payload_type="VOTE_RECEIPT",
            author_id="node_us_east",
            payload_sha256="sha_vote_101",
            parent_cids=[]
        )
        id_a = node_a_rec.cid
        node_b_rec = self.node_b.sync_engine.insert_receipt(
            epoch_index=1,
            payload_type="SANDBOX_RECEIPT",
            author_id="node_eu_west",
            payload_sha256="sha_sb_202",
            parent_cids=[]
        )
        id_b = node_b_rec.cid

        # Start background TCP listener on node B
        self.node_b.start_listener()
        time.sleep(0.1)

        # Node A gossips to Node B
        receipt = self.node_a.send_gossip_to_peer("127.0.0.1", 9212)
        self.assertIsInstance(receipt, MerkleSyncReceipt)
        self.assertEqual(receipt.local_peer_id, "node_us_east")
        self.assertEqual(receipt.remote_peer_id, "node_eu_west")
        
        # Verify two-way synchronization: Node B has Node A's node AND Node A has Node B's node
        self.assertIn(id_a, self.node_b.sync_engine.dag_nodes)
        self.assertIn(id_b, self.node_a.sync_engine.dag_nodes)
        
        # Verify both Merkle roots are identical and sync converged
        self.assertEqual(self.node_a.sync_engine.get_merkle_root_cid(), self.node_b.sync_engine.get_merkle_root_cid())
        self.assertTrue(receipt.sync_converged)

    def test_signed_gossip_message_creation_and_handling(self):
        signed_a, signed_b = self._signed_nodes()
        try:
            node_node = signed_a.sync_engine.insert_receipt(
                epoch_index=1,
                payload_type="VOTE_RECEIPT",
                author_id="node_us_east",
                payload_sha256="sha_signed_vote",
                parent_cids=[]
            )
            msg = signed_a.create_announcement_message()
            raw = signed_a.encode_outbound_message(msg)
            parsed = SignedGossipEnvelope(**json.loads(raw.decode("utf-8")))
            self.assertEqual(parsed.signature_algorithm, "ED25519")

            ack = signed_b.handle_inbound_message(raw)
            self.assertEqual(ack.message_type, "ACK")
            self.assertIn(node_node.cid, signed_b.sync_engine.dag_nodes)
        finally:
            signed_a.stop_listener()
            signed_b.stop_listener()

    def test_unsigned_message_rejected_when_signatures_required(self):
        signed_a, signed_b = self._signed_nodes()
        try:
            msg = signed_a.create_announcement_message()
            with self.assertRaises(GossipSecurityError) as ctx:
                signed_b.handle_inbound_message(msg.model_dump_json().encode("utf-8"))
            self.assertIn("unsigned inbound gossip rejected", str(ctx.exception))
        finally:
            signed_a.stop_listener()
            signed_b.stop_listener()

    def test_unknown_signed_peer_rejected(self):
        signed_a, signed_b = self._signed_nodes()
        signed_b.trusted_peer_public_keys.clear()
        try:
            raw = signed_a.encode_outbound_message(signed_a.create_announcement_message())
            with self.assertRaises(GossipSecurityError) as ctx:
                signed_b.handle_inbound_message(raw)
            self.assertIn("unknown or untrusted gossip peer", str(ctx.exception))
        finally:
            signed_a.stop_listener()
            signed_b.stop_listener()

    def test_tampered_signed_payload_rejected(self):
        signed_a, signed_b = self._signed_nodes()
        try:
            raw = signed_a.encode_outbound_message(signed_a.create_announcement_message())
            envelope = SignedGossipEnvelope(**json.loads(raw.decode("utf-8")))
            tampered_message = envelope.message.model_copy(update={"merkle_root_cid": "tampered_root"})
            tampered_envelope = envelope.model_copy(update={"message": tampered_message})
            with self.assertRaises(GossipSecurityError) as ctx:
                signed_b.handle_inbound_message(tampered_envelope.model_dump_json().encode("utf-8"))
            self.assertIn("payload digest mismatch", str(ctx.exception))
        finally:
            signed_a.stop_listener()
            signed_b.stop_listener()

    def test_replayed_signed_message_rejected(self):
        signed_a, signed_b = self._signed_nodes()
        try:
            raw = signed_a.encode_outbound_message(signed_a.create_announcement_message())
            signed_b.handle_inbound_message(raw)
            with self.assertRaises(GossipSecurityError) as ctx:
                signed_b.handle_inbound_message(raw)
            self.assertIn("replayed signed gossip message rejected", str(ctx.exception))
        finally:
            signed_a.stop_listener()
            signed_b.stop_listener()

    def test_live_socket_signed_gossip_sync(self):
        signed_a, signed_b = self._signed_nodes(port_a=9231, port_b=9232)
        try:
            id_a = signed_a.sync_engine.insert_receipt(
                epoch_index=1,
                payload_type="VOTE_RECEIPT",
                author_id="node_us_east",
                payload_sha256="sha_signed_vote_101",
                parent_cids=[]
            ).cid
            id_b = signed_b.sync_engine.insert_receipt(
                epoch_index=1,
                payload_type="SANDBOX_RECEIPT",
                author_id="node_eu_west",
                payload_sha256="sha_signed_sb_202",
                parent_cids=[]
            ).cid

            signed_b.start_listener()
            time.sleep(0.1)

            receipt = signed_a.send_gossip_to_peer("127.0.0.1", 9232)
            self.assertTrue(receipt.sync_converged)
            self.assertIn(id_a, signed_b.sync_engine.dag_nodes)
            self.assertIn(id_b, signed_a.sync_engine.dag_nodes)
        finally:
            signed_a.stop_listener()
            signed_b.stop_listener()

if __name__ == "__main__":
    unittest.main()
