"""
Cryptographic Checkout & Fulfillment Receipt Compiler & Verifier.

Uses Ed25519 digital signatures (`cryptography.hazmat.primitives.asymmetric.ed25519`)
and a domain-separated SHA-256 Merkle Evidence Tree over three canonical leaves:
  1. `checkout_auth`: 3DS2 status (Y/N), ECI (05/06/07), CAVV, device_id, ip_address,
     avs_cvv_match, account_id, shipping_address_hash, amount_inr, timestamp.
  2. `delivery_proof`: carrier signed GPS coordinates, OTP-verified handoff flag,
     recipient signature/photo hash, delivery timestamp, delivered flag.
  3. `post_purchase_usage`: app login/session events from device_id/ip_address
     after transaction timestamp.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

LEAF_ORDER = ("checkout_auth", "delivery_proof", "post_purchase_usage")


def as_bool(value: Any) -> bool:
    """Strict JSON boolean: bool("false") is True, so strings must not be coerced."""
    if isinstance(value, bool):
        return value
    raise ValueError(f"expected a JSON boolean, got {value!r}")


def as_amount(value: Any) -> float:
    """A finite, non-negative amount; float() alone accepts "nan" and "inf"."""
    amount = float(value)
    if not math.isfinite(amount) or amount < 0:
        raise ValueError(f"amount must be a finite non-negative number, got {value!r}")
    return amount


def canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON serialization for cryptographic hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hash_leaf(leaf_name: str, payload: Dict[str, Any]) -> str:
    """Compute domain-separated SHA-256 leaf digest: H(0x00 || leaf_name || ':' || canonical_json)."""
    h = hashlib.sha256()
    h.update(b"\x00")
    h.update(leaf_name.encode("utf-8"))
    h.update(b":")
    h.update(canonical_json_bytes(payload))
    return h.hexdigest()


def hash_internal(left_hex: str, right_hex: str) -> str:
    """Compute domain-separated SHA-256 internal node digest: H(0x01 || left || right)."""
    h = hashlib.sha256()
    h.update(b"\x01")
    h.update(bytes.fromhex(left_hex))
    h.update(bytes.fromhex(right_hex))
    return h.hexdigest()


@dataclass
class CheckoutAuthLeaf:
    txn_id: str
    account_id: str
    amount_inr: float
    three_ds_status: str  # "Y" or "N"
    eci: str  # "05" (fully authenticated), "06" (attempted), "07" (non-3DS)
    cavv: str
    device_id: str
    ip_address: str
    avs_cvv_match: bool
    shipping_address_hash: str
    timestamp: int  # Unix epoch seconds
    credit_refund_processed: bool = False
    credit_arn: Optional[str] = None
    cancelled_before_billing: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CheckoutAuthLeaf":
        return cls(
            txn_id=str(data["txn_id"]),
            account_id=str(data["account_id"]),
            amount_inr=as_amount(data["amount_inr"]),
            three_ds_status=str(data["three_ds_status"]),
            eci=str(data["eci"]),
            cavv=str(data.get("cavv", "")),
            device_id=str(data["device_id"]),
            ip_address=str(data["ip_address"]),
            avs_cvv_match=as_bool(data["avs_cvv_match"]),
            shipping_address_hash=str(data.get("shipping_address_hash", "")),
            timestamp=int(data["timestamp"]),
            credit_refund_processed=as_bool(data.get("credit_refund_processed", False)),
            credit_arn=data.get("credit_arn"),
            cancelled_before_billing=as_bool(data.get("cancelled_before_billing", False)),
        )


@dataclass
class DeliveryProofLeaf:
    delivered: bool
    carrier_signed_gps: str  # e.g. "12.9716,77.5946"
    otp_verified_handoff: bool
    recipient_signature_hash: str
    delivery_timestamp: int
    as_described_qc_passed: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeliveryProofLeaf":
        return cls(
            delivered=as_bool(data["delivered"]),
            carrier_signed_gps=str(data.get("carrier_signed_gps", "")),
            otp_verified_handoff=as_bool(data["otp_verified_handoff"]),
            recipient_signature_hash=str(data.get("recipient_signature_hash", "")),
            delivery_timestamp=int(data.get("delivery_timestamp", 0)),
            as_described_qc_passed=as_bool(data.get("as_described_qc_passed", True)),
        )


@dataclass
class UsageEvent:
    event_type: str
    device_id: str
    ip_address: str
    timestamp: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UsageEvent":
        return cls(
            event_type=str(data["event_type"]),
            device_id=str(data["device_id"]),
            ip_address=str(data["ip_address"]),
            timestamp=int(data["timestamp"]),
        )


@dataclass
class PostPurchaseUsageLeaf:
    events: List[UsageEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"events": [e.to_dict() for e in self.events]}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PostPurchaseUsageLeaf":
        events = [UsageEvent.from_dict(e) for e in data.get("events", [])]
        return cls(events=events)


@dataclass
class VerificationResult:
    valid: bool
    merkle_valid: bool
    signature_valid: bool
    inclusion_proofs_valid: bool
    tampered_leaves: List[str]
    computed_merkle_root: str
    claimed_merkle_root: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidencePacket:
    txn_id: str
    checkout_auth: CheckoutAuthLeaf
    delivery_proof: DeliveryProofLeaf
    post_purchase_usage: PostPurchaseUsageLeaf
    leaf_hashes: Dict[str, str]
    merkle_root: str
    inclusion_proofs: Dict[str, List[Dict[str, str]]]
    ed25519_signature: str
    public_key_hex: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "txn_id": self.txn_id,
            "checkout_auth": self.checkout_auth.to_dict(),
            "delivery_proof": self.delivery_proof.to_dict(),
            "post_purchase_usage": self.post_purchase_usage.to_dict(),
            "leaf_hashes": dict(self.leaf_hashes),
            "merkle_root": self.merkle_root,
            "inclusion_proofs": {k: list(v) for k, v in self.inclusion_proofs.items()},
            "ed25519_signature": self.ed25519_signature,
            "public_key_hex": self.public_key_hex,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidencePacket":
        return cls(
            txn_id=str(data["txn_id"]),
            checkout_auth=CheckoutAuthLeaf.from_dict(data["checkout_auth"]),
            delivery_proof=DeliveryProofLeaf.from_dict(data["delivery_proof"]),
            post_purchase_usage=PostPurchaseUsageLeaf.from_dict(data["post_purchase_usage"]),
            leaf_hashes=dict(data["leaf_hashes"]),
            merkle_root=str(data["merkle_root"]),
            inclusion_proofs=dict(data["inclusion_proofs"]),
            ed25519_signature=str(data["ed25519_signature"]),
            public_key_hex=str(data["public_key_hex"]),
        )


class MerchantSigner:
    """Ed25519 keypair manager for signing and verifying EvidencePackets."""

    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None) -> None:
        # A fresh random key unless one is supplied. Never derive keys from a seed in the code:
        # anyone reading it could sign "evidence" as the merchant.
        self._private_key = private_key if private_key is not None else Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

    @classmethod
    def generate_random(cls) -> "MerchantSigner":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> "MerchantSigner":
        """Load a 32-byte Ed25519 private seed given as 64 hex characters (e.g. from a secret store)."""
        return cls(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)))

    @property
    def public_key_hex(self) -> str:
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    def sign_message(self, message: bytes) -> str:
        return self._private_key.sign(message).hex()


def build_merkle_tree(
    leaf_hashes: Dict[str, str],
) -> tuple[str, Dict[str, List[Dict[str, str]]]]:
    """
    Build a 3-leaf binary Merkle tree over:
      L1 = leaf_hashes["checkout_auth"]
      L2 = leaf_hashes["delivery_proof"]
      L3 = leaf_hashes["post_purchase_usage"]
    Tree topology:
      N12 = H(0x01 || L1 || L2)
      Root = H(0x01 || N12 || L3)
    Returns (merkle_root, inclusion_proofs).
    """
    l1 = leaf_hashes["checkout_auth"]
    l2 = leaf_hashes["delivery_proof"]
    l3 = leaf_hashes["post_purchase_usage"]

    n12 = hash_internal(l1, l2)
    root = hash_internal(n12, l3)

    proofs: Dict[str, List[Dict[str, str]]] = {
        "checkout_auth": [
            {"position": "right", "hash": l2},
            {"position": "right", "hash": l3},
        ],
        "delivery_proof": [
            {"position": "left", "hash": l1},
            {"position": "right", "hash": l3},
        ],
        "post_purchase_usage": [
            {"position": "left", "hash": n12},
        ],
    }
    return root, proofs


def verify_inclusion_proof(
    leaf_hash_hex: str,
    proof: List[Dict[str, str]],
    expected_root_hex: str,
) -> bool:
    """Verify a Merkle inclusion proof for a single leaf against expected_root_hex."""
    current = leaf_hash_hex
    try:
        for step in proof:
            sibling = step["hash"]
            pos = step["position"]
            if pos == "left":
                current = hash_internal(sibling, current)
            elif pos == "right":
                current = hash_internal(current, sibling)
            else:
                return False
    except (KeyError, ValueError):
        return False
    return current == expected_root_hex


def _signing_payload(txn_id: str, merkle_root: str) -> bytes:
    return f"DISPUTEARB_RECEIPT_V1|{txn_id}|{merkle_root}".encode("utf-8")


def compile_evidence_packet(
    checkout_auth: CheckoutAuthLeaf,
    delivery_proof: DeliveryProofLeaf,
    post_purchase_usage: PostPurchaseUsageLeaf,
    signer: MerchantSigner,
) -> EvidencePacket:
    """Compile a cryptographically signed EvidencePacket with SHA-256 Merkle proofs."""

    leaf_hashes = {
        "checkout_auth": hash_leaf("checkout_auth", checkout_auth.to_dict()),
        "delivery_proof": hash_leaf("delivery_proof", delivery_proof.to_dict()),
        "post_purchase_usage": hash_leaf("post_purchase_usage", post_purchase_usage.to_dict()),
    }
    merkle_root, inclusion_proofs = build_merkle_tree(leaf_hashes)
    signature = signer.sign_message(_signing_payload(checkout_auth.txn_id, merkle_root))

    return EvidencePacket(
        txn_id=checkout_auth.txn_id,
        checkout_auth=checkout_auth,
        delivery_proof=delivery_proof,
        post_purchase_usage=post_purchase_usage,
        leaf_hashes=leaf_hashes,
        merkle_root=merkle_root,
        inclusion_proofs=inclusion_proofs,
        ed25519_signature=signature,
        public_key_hex=signer.public_key_hex,
    )


def verify_evidence_packet(
    packet: EvidencePacket,
    trusted_public_key_hex: str,
) -> VerificationResult:
    """
    Verify an EvidencePacket's leaf integrity, Merkle inclusion proofs, Merkle root,
    and Ed25519 digital signature. Any mutation to payload fields, leaf hashes,
    Merkle root, or signature is caught immediately.

    `trusted_public_key_hex` is the merchant key the verifier already holds. The packet's own
    `public_key_hex` is never trusted: anyone can re-sign altered evidence with a key of their own.
    """
    recomputed_leaves = {
        "checkout_auth": hash_leaf("checkout_auth", packet.checkout_auth.to_dict()),
        "delivery_proof": hash_leaf("delivery_proof", packet.delivery_proof.to_dict()),
        "post_purchase_usage": hash_leaf("post_purchase_usage", packet.post_purchase_usage.to_dict()),
    }

    tampered_leaves: List[str] = []
    for leaf_name in LEAF_ORDER:
        claimed_leaf_hash = packet.leaf_hashes.get(leaf_name, "")
        if recomputed_leaves[leaf_name] != claimed_leaf_hash:
            tampered_leaves.append(leaf_name)

    computed_root, _ = build_merkle_tree(recomputed_leaves)
    merkle_valid = (computed_root == packet.merkle_root) and (len(tampered_leaves) == 0)

    # Also check each leaf's inclusion proof against packet.merkle_root
    inclusion_proofs_valid = True
    for leaf_name in LEAF_ORDER:
        proof = packet.inclusion_proofs.get(leaf_name)
        if not proof or not verify_inclusion_proof(
            recomputed_leaves[leaf_name], proof, packet.merkle_root
        ):
            inclusion_proofs_valid = False
            if leaf_name not in tampered_leaves:
                tampered_leaves.append(leaf_name)

    if not inclusion_proofs_valid:
        merkle_valid = False

    # Verify Ed25519 signature over (txn_id, claimed_merkle_root) AND check txn_id consistency
    pub_hex = trusted_public_key_hex
    signature_valid = False
    if packet.txn_id != packet.checkout_auth.txn_id:
        if "checkout_auth" not in tampered_leaves:
            tampered_leaves.append("checkout_auth")
        merkle_valid = False

    try:
        pub_bytes = bytes.fromhex(pub_hex)
        sig_bytes = bytes.fromhex(packet.ed25519_signature)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, _signing_payload(packet.txn_id, packet.merkle_root))
        # Also verify signature against the recomputed root so an attacker who re-computes
        # Merkle root without the private key fails signature verification
        if computed_root == packet.merkle_root:
            signature_valid = True
        else:
            signature_valid = False
    except (TypeError, ValueError, InvalidSignature):
        signature_valid = False

    valid = merkle_valid and signature_valid and inclusion_proofs_valid and (len(tampered_leaves) == 0)
    if valid:
        reason = "All 3 Merkle leaves, inclusion proofs, and Ed25519 signature verified."
    elif tampered_leaves and not signature_valid:
        reason = (
            f"Cryptographic tampering detected in leaves {tampered_leaves} "
            "and/or invalid Ed25519 signature."
        )
    elif tampered_leaves:
        reason = f"Merkle leaf hash mismatch detected in leaves: {tampered_leaves}."
    else:
        reason = "Invalid Ed25519 digital signature over Merkle root."

    return VerificationResult(
        valid=valid,
        merkle_valid=merkle_valid,
        signature_valid=signature_valid,
        inclusion_proofs_valid=inclusion_proofs_valid,
        tampered_leaves=tampered_leaves,
        computed_merkle_root=computed_root,
        claimed_merkle_root=packet.merkle_root,
        reason=reason,
    )
