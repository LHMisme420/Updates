# Updates
Immutability updates
#!/usr/bin/env python3
"""
DLT-style Audit Log Skeleton for DECF / IMS

Features:
1. Log entry hashing (already possible in your system)
2. Previous-hash pointer (the missing piece)
3. Distributed replication to 3+ nodes (stubs)
4. Verification / challenge service (missing piece)
5. Immutability model: attacker must break all replicas + recompute chain
"""

import hashlib
import json
import random
import time
from typing import Any, Dict, List, Optional, Protocol


# ============================================================
# 1. CORE: Log Entry
# ============================================================

class LogEntry:
    """
    Represents a single log event in the chain.
    """
    def __init__(
        self,
        index: int,
        payload: Dict[str, Any],
        prev_hash: str,
        ts: Optional[float] = None,
    ) -> None:
        self.index = index
        self.payload = payload
        self.prev_hash = prev_hash
        self.ts = ts or time.time()
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        """
        Deterministic hash:
        Hn = SHA256( json(payload) + prev_hash + str(index) + str(ts) )
        """
        body = {
            "index": self.index,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "ts": self.ts,
        }
        # Ensure stable ordering
        serialized = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
            "ts": self.ts,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "LogEntry":
        obj = LogEntry(
            index=data["index"],
            payload=data["payload"],
            prev_hash=data["prev_hash"],
            ts=data["ts"],
        )
        # Allow recovery from storage: trust stored hash
        obj.hash = data["hash"]
        return obj


# ============================================================
# 2. STORAGE INTERFACE (so we can plug 3 different backends)
# ============================================================

class StorageBackend(Protocol):
    """
    Abstract storage interface. You will implement 3 of these
    (e.g., NodeAStorage, NodeBStorage, NodeCStorage) against your real DBs.
    """
    def write_entry(self, entry: LogEntry) -> None:
        ...

    def read_entry(self, index: int) -> Optional[LogEntry]:
        ...

    def get_last_index(self) -> int:
        ...

    def get_all_hashes(self) -> Dict[int, str]:
        """
        For challenge verification: {index: hash}
        """
        ...


# ============================================================
# 3. IN-MEMORY MOCK STORAGE (for local testing)
# ============================================================

class InMemoryStorage(StorageBackend):
    def __init__(self, name: str) -> None:
        self.name = name
        self._store: Dict[int, Dict[str, Any]] = {}

    def write_entry(self, entry: LogEntry) -> None:
        self._store[entry.index] = entry.to_dict()

    def read_entry(self, index: int) -> Optional[LogEntry]:
        data = self._store.get(index)
        if not data:
            return None
        return LogEntry.from_dict(data)

    def get_last_index(self) -> int:
        if not self._store:
            return -1
        return max(self._store.keys())

    def get_all_hashes(self) -> Dict[int, str]:
        return {i: d["hash"] for i, d in self._store.items()}


# ============================================================
# 4. REPLICA MANAGER (3-node write)
# ============================================================

class ReplicaManager:
    """
    Handles writing each new chained log entry to multiple nodes.
    Policy here: 2-of-3 quorum is a commit.
    """
    def __init__(self, replicas: List[StorageBackend], quorum: int = 2) -> None:
        self.replicas = replicas
        self.quorum = quorum

    def write_to_replicas(self, entry: LogEntry) -> bool:
        successes = 0
        for r in self.replicas:
            try:
                r.write_entry(entry)
                successes += 1
            except Exception:
                # TODO: add logging / DLQ
                pass
        return successes >= self.quorum

    def get_consensus_last_index(self) -> int:
        """
        Conservative: take the minimum last index across replicas.
        That way, we only build on what everyone (or most) has.
        """
        indices = [r.get_last_index() for r in self.replicas]
        return min(indices) if indices else -1


# ============================================================
# 5. LEDGER (log-chain builder)
# ============================================================

class Ledger:
    """
    The main DLT-like log component.
    - builds the chain
    - enforces prev_hash
    - sends entries to replicas
    """
    GENESIS_HASH = "0" * 64  # 64-char dummy for index 0

    def __init__(self, replica_manager: ReplicaManager) -> None:
        self.replicas = replica_manager

    def append_event(self, payload: Dict[str, Any]) -> LogEntry:
        """
        Create new chained log entry and push to replicas.
        """
        # Figure out the last
#!/usr/bin/env python3
"""
DLT-style Audit Log (Hardened) for DECF / IMS

Adds:
- Per-entry signatures (node-signed)
- Merkle root computation
- Notarization stub for external anchoring
- Crypto provider abstraction
"""

import hashlib
import hmac
import json
import random
import time
from typing import Any, Dict, List, Optional, Protocol


# ============================================================
# 0. CRYPTO PROVIDER (pluggable)
# ============================================================

class CryptoProvider(Protocol):
    """
    Abstracts signing and verifying.
    In prod: back this by HSM/KMS or real Ed25519.
    Here: HMAC placeholder.
    """
    def sign(self, message: bytes) -> str:
        ...

    def verify(self, message: bytes, signature: str) -> bool:
        ...


class HMACCryptoProvider:
    """
    Simple HMAC-based signer for demo.
    Replace with Ed25519 or ECDSA in production.
    """
    def __init__(self, secret: str):
        self.secret = secret.encode("utf-8")

    def sign(self, message: bytes) -> str:
        digest = hmac.new(self.secret, message, hashlib.sha3_256).hexdigest()
        return digest

    def verify(self, message: bytes, signature: str) -> bool:
        expected = self.sign(message)
        return hmac.compare_digest(expected, signature)


# ============================================================
# 1. CORE: Log Entry
# ============================================================

class LogEntry:
    """
    A single, chained, signed log event.
    """
    def __init__(
        self,
        index: int,
        payload: Dict[s]()
import base64
import json
import requests
from typing import Dict, Any

# If you're using solana-py, you can swap this out for real Transaction objects.
# This version shows the raw JSON-RPC flow for clarity.

class SolanaNotarizer:
    """
    Publishes a Merkle root to Solana via the Memo program.

    Strategy:
    - Build a transaction with 1 instruction: memo(root_payload)
    - Sign it with a local private key (ed25519) – here we assume you've got it as base58/base64
    - Send via sendTransaction
    """

    def __init__(self, rpc_url: str, payer_private_key: bytes):
        """
        rpc_url: e.g. "https://api.devnet.solana.com" (or your provider endpoint)
        payer_private_key: 64-byte ed25519 private key (seed+pub) as raw bytes
        NOTE: in real env, load from KMS/HSM, not from disk.
        """
        self.rpc_url = rpc_url
        self.payer_private_
notarizer = Notarizer("demo-ledger")
print("Merkle+Notarize:", verifier.merkle_and_notarize(notarizer))
from datetime import datetime

# your Solana endpoint (devnet/testnet/mainnet-beta or a provider)
SOLANA_RPC = "https://api.devnet.solana.com"  # pick your cluster

# load your payer key (DO NOT hardcode in real env)
with open("solana-payer-keypair.bin", "rb") as f:
    payer_key = f.read()

sol_notarizer = SolanaNotarizer(SOLANA_RPC, payer_key)
root_result = verifier.merkle_and_notarize(sol_notarizer)
print(root_result)
