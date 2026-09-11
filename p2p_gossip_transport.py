import hashlib
import json
import socket
import threading
import time
import binascii
from typing import Dict, Any, List, Optional, Tuple, Set
from council_contracts import ImmutableContract
from distributed_merkle_state_sync import DistributedMerkleStateSync, MerkleDAGNode, MerkleSyncReceipt

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
except Exception:  # pragma: no cover - exercised only when PyNaCl is absent
    BadSignatureError = None
    SigningKey = None
    VerifyKey = None

class GossipMessage(ImmutableContract):
    message_type: str  # "ANNOUNCE_ROOT", "REQUEST_RANGE", "RECONCILE_NODES", "ACK"
    sender_peer_id: str
    epoch_index: int
    merkle_root_cid: str
    vector_clock: Dict[str, int]
    payload_nodes: List[MerkleDAGNode]
    timestamp: float

class SignedGossipEnvelope(ImmutableContract):
    envelope_type: str = "SIGNED_GOSSIP"
    message_id: str
    sender_peer_id: str
    signature_algorithm: str = "ED25519"
    signed_payload_sha256: str
    detached_signature: str
    message: GossipMessage
    created_at: float

class GossipSecurityError(Exception):
    pass

def _require_pynacl() -> None:
    if SigningKey is None or VerifyKey is None:
        raise RuntimeError("PyNaCl is required for Ed25519 gossip signatures")

def _decode_key_material(key_material: str) -> bytes:
    cleaned = key_material.strip()
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return cleaned.encode("utf-8")

class P2PGossipTransportNode:
    """
    Live Peer-to-Peer Receipt Gossip Transport Node:
    - Encapsulates DistributedMerkleStateSync for local MPPT DAG storage and anti-entropy diffs.
    - Listens on TCP sockets for gossip messages from peer nodes.
    - Dispatches range-based reconciliation payloads and synchronizes vector clocks.
    - Emits verifiable MerkleSyncReceipts.
    """

    def __init__(
        self,
        peer_id: str,
        host: str = "127.0.0.1",
        port: int = 9100,
        private_key: Optional[str] = None,
        trusted_peer_public_keys: Optional[Dict[str, str]] = None,
        require_signed_messages: bool = False,
        max_clock_skew_sec: float = 300.0
    ):
        self.peer_id = peer_id
        self.host = host
        self.port = port
        self.private_key = private_key
        self.trusted_peer_public_keys = trusted_peer_public_keys or {}
        self.require_signed_messages = require_signed_messages
        self.max_clock_skew_sec = max_clock_skew_sec
        self.sync_engine = DistributedMerkleStateSync(peer_id=peer_id)
        self.known_peers: Set[Tuple[str, int]] = set()
        self.seen_signed_message_ids: Set[str] = set()
        self._server_socket: Optional[socket.socket] = None
        self._is_running: bool = False
        self._listener_thread: Optional[threading.Thread] = None

    def add_peer(self, host: str, port: int) -> None:
        """Registers a known peer address for gossip replication."""
        self.known_peers.add((host, port))

    @staticmethod
    def derive_public_key(private_key: str) -> str:
        _require_pynacl()
        private_bytes = _decode_key_material(private_key)
        if len(private_bytes) == 64:
            private_bytes = private_bytes[:32]
        return SigningKey(private_bytes).verify_key.encode().hex()

    def register_trusted_peer(self, peer_id: str, public_key: str) -> None:
        self.trusted_peer_public_keys[peer_id] = public_key

    def _canonical_message_bytes(self, message: GossipMessage) -> bytes:
        return json.dumps(message.model_dump(), sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

    def create_signed_envelope(self, message: GossipMessage) -> SignedGossipEnvelope:
        """Wraps a gossip message in an Ed25519 detached-signature envelope."""
        _require_pynacl()
        if not self.private_key:
            raise GossipSecurityError("cannot sign gossip message without a private key")
        if message.sender_peer_id != self.peer_id:
            raise GossipSecurityError("cannot sign message for a different sender_peer_id")

        payload_bytes = self._canonical_message_bytes(message)
        private_bytes = _decode_key_material(self.private_key)
        if len(private_bytes) == 64:
            private_bytes = private_bytes[:32]
        signature = SigningKey(private_bytes).sign(payload_bytes).signature.hex()
        return SignedGossipEnvelope(
            message_id=hashlib.sha256(f"{self.peer_id}:{time.time()}:{message.merkle_root_cid}".encode("utf-8")).hexdigest(),
            sender_peer_id=self.peer_id,
            signed_payload_sha256=hashlib.sha256(payload_bytes).hexdigest(),
            detached_signature=signature,
            message=message,
            created_at=time.time()
        )

    def verify_signed_envelope(self, envelope: SignedGossipEnvelope) -> GossipMessage:
        """Validates sender identity, trust-store binding, payload digest, signature, and replay."""
        _require_pynacl()
        if envelope.signature_algorithm != "ED25519":
            raise GossipSecurityError("unsupported gossip signature algorithm")
        if envelope.sender_peer_id != envelope.message.sender_peer_id:
            raise GossipSecurityError("signed envelope sender does not match message sender")
        if envelope.message_id in self.seen_signed_message_ids:
            raise GossipSecurityError("replayed signed gossip message rejected")
        now = time.time()
        if envelope.created_at > now + self.max_clock_skew_sec:
            raise GossipSecurityError("signed gossip message timestamp is in the future")

        public_key = self.trusted_peer_public_keys.get(envelope.sender_peer_id)
        if not public_key:
            raise GossipSecurityError(f"unknown or untrusted gossip peer '{envelope.sender_peer_id}'")

        payload_bytes = self._canonical_message_bytes(envelope.message)
        if hashlib.sha256(payload_bytes).hexdigest() != envelope.signed_payload_sha256:
            raise GossipSecurityError("signed gossip payload digest mismatch")

        try:
            VerifyKey(_decode_key_material(public_key)).verify(payload_bytes, bytes.fromhex(envelope.detached_signature))
        except (BadSignatureError, ValueError, binascii.Error):
            raise GossipSecurityError("signed gossip signature verification failed")

        self.seen_signed_message_ids.add(envelope.message_id)
        return envelope.message

    def encode_outbound_message(self, message: GossipMessage) -> bytes:
        if self.private_key:
            envelope = self.create_signed_envelope(message)
            return envelope.model_dump_json().encode("utf-8")
        if self.require_signed_messages:
            raise GossipSecurityError("unsigned outbound gossip disabled")
        return message.model_dump_json().encode("utf-8")

    def decode_inbound_message(self, raw_bytes: bytes) -> GossipMessage:
        msg_dict = json.loads(raw_bytes.decode("utf-8"))
        if msg_dict.get("envelope_type") == "SIGNED_GOSSIP":
            return self.verify_signed_envelope(SignedGossipEnvelope(**msg_dict))
        if self.require_signed_messages:
            raise GossipSecurityError("unsigned inbound gossip rejected")
        return GossipMessage(**msg_dict)

    def create_announcement_message(self) -> GossipMessage:
        """Creates an ANNOUNCE_ROOT gossip message with the local Merkle root and vector clock."""
        root_cid = self.sync_engine.get_merkle_root_cid()
        return GossipMessage(
            message_type="ANNOUNCE_ROOT",
            sender_peer_id=self.peer_id,
            epoch_index=1,
            merkle_root_cid=root_cid,
            vector_clock=self.sync_engine.vector_clock.copy(),
            payload_nodes=list(self.sync_engine.dag_nodes.values()),
            timestamp=time.time()
        )

    def handle_inbound_message(self, raw_bytes: bytes) -> GossipMessage:
        """Processes an inbound gossip message, merges missing DAG nodes, and returns ACK with complete local nodes."""
        msg = self.decode_inbound_message(raw_bytes)

        # Merge inbound DAG nodes from sender
        for node in msg.payload_nodes:
            self.sync_engine.add_external_node(node)

        # Reconcile vector clocks (taking element-wise max)
        for p, seq in msg.vector_clock.items():
            self.sync_engine.vector_clock[p] = max(self.sync_engine.vector_clock.get(p, 0), seq)

        # Increment local sequence
        self.sync_engine.vector_clock[self.peer_id] = self.sync_engine.vector_clock.get(self.peer_id, 0) + 1

        return GossipMessage(
            message_type="ACK",
            sender_peer_id=self.peer_id,
            epoch_index=msg.epoch_index,
            merkle_root_cid=self.sync_engine.get_merkle_root_cid(),
            vector_clock=self.sync_engine.vector_clock.copy(),
            payload_nodes=list(self.sync_engine.dag_nodes.values()),
            timestamp=time.time()
        )

    def start_listener(self) -> None:
        """Starts a background TCP listener for inbound P2P gossip traffic."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        self._is_running = True

        def _listen_loop():
            while self._is_running:
                try:
                    self._server_socket.settimeout(0.5)
                    client, _ = self._server_socket.accept()
                    data = client.recv(65536)
                    if data:
                        resp = self.handle_inbound_message(data)
                        client.sendall(self.encode_outbound_message(resp))
                    client.close()
                except socket.timeout:
                    continue
                except Exception:
                    break

        self._listener_thread = threading.Thread(target=_listen_loop, daemon=True)
        self._listener_thread.start()

    def stop_listener(self) -> None:
        """Stops the background TCP listener cleanly."""
        self._is_running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        if self._listener_thread:
            self._listener_thread.join(timeout=1.0)

    def send_gossip_to_peer(self, peer_host: str, peer_port: int) -> MerkleSyncReceipt:
        """Sends a live gossip announcement to a remote peer, merges response DAG nodes, and achieves two-way convergence."""
        msg = self.create_announcement_message()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((peer_host, peer_port))
        s.sendall(self.encode_outbound_message(msg))
        resp_data = s.recv(65536)
        s.close()

        resp_msg = self.decode_inbound_message(resp_data)

        # Merge inbound DAG nodes from peer's ACK response into local DAG
        for node in resp_msg.payload_nodes:
            self.sync_engine.add_external_node(node)

        # Synchronize vector clock
        for p, seq in resp_msg.vector_clock.items():
            self.sync_engine.vector_clock[p] = max(self.sync_engine.vector_clock.get(p, 0), seq)
        self.sync_engine.vector_clock[self.peer_id] = self.sync_engine.vector_clock.get(self.peer_id, 0) + 1

        local_root = self.sync_engine.get_merkle_root_cid()
        remote_root = resp_msg.merkle_root_cid
        converged = (local_root == remote_root)

        receipt = MerkleSyncReceipt(
            sync_session_id=f"gossip_live_{int(time.time()*1000)}",
            local_peer_id=self.peer_id,
            remote_peer_id=resp_msg.sender_peer_id,
            local_root_cid=local_root,
            remote_root_cid=remote_root,
            synchronized_nodes_count=len(self.sync_engine.dag_nodes),
            symmetric_diff_cids=[],
            sync_converged=converged,
            receipt_sha256=hashlib.sha256(f"{self.peer_id}:{resp_msg.sender_peer_id}:{time.time()}".encode("utf-8")).hexdigest(),
            synced_at=time.time()
        )
        return receipt
