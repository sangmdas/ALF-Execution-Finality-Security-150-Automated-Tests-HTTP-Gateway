"""ALF demonstration only: in-process observation and HMAC are NOT a protected execution domain.

Models selected relationships from the ALF Election disclosure: actual activation
measurements (ALF-I/E), pending-output binding (ALF-O), authenticated validation
receipts, separate scoped enablement, and independent sink-side checking.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
from hashlib import sha256
import hmac
import json
import threading
import time
from typing import Mapping

class Denied(Exception):
    """A mandatory verification condition was not satisfied."""


def canonical(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(data: object) -> str:
    return sha256(canonical(data)).hexdigest()


def signature(secret: bytes, data: object) -> str:
    return hmac.new(secret, canonical(data), sha256).hexdigest()


@dataclass(frozen=True)
class Operation:
    operation_id: str
    output: str
    destination: str
    sink: str = "feed-gateway"
    def descriptor(self) -> dict[str, str]:
        return {"operation_id": self.operation_id, "output": self.output,
                "destination": self.destination, "sink": self.sink}
    @property
    def commitment(self) -> str:
        return digest(self.descriptor())


@dataclass(frozen=True)
class ALFMeasurement:
    components: tuple[tuple[str, str, int], ...]  # (stage, activated config id, protected generation)
    @property
    def alf_i(self) -> str:
        return digest([(stage, config) for stage, config, _ in self.components])
    @property
    def alf_e(self) -> str:
        return digest(self.components)


class ActivationController:
    """Simulated independent observer. Not secure against local process compromise."""
    def __init__(self, initial: Mapping[str, str]):
        self._lock = threading.RLock()
        self._active = {name: (config, 1) for name, config in initial.items()}
    def measure(self) -> ALFMeasurement:
        with self._lock:
            return ALFMeasurement(tuple(sorted((n, c, g) for n, (c, g) in self._active.items())))
    def hot_swap(self, stage: str, new_config: str) -> None:
        with self._lock:
            if stage not in self._active:
                raise KeyError(stage)
            _, generation = self._active[stage]
            self._active[stage] = (new_config, generation + 1)
    def is_current(self, measurement: ALFMeasurement) -> bool:
        return hmac.compare_digest(measurement.alf_e, self.measure().alf_e)


class ApprovalRegistry:
    """Approval is an external policy input, NOT a determination of viewpoint correctness."""
    def __init__(self, approved: Mapping[str, str]):
        self._lock = threading.RLock()
        self.approved = dict(approved)
        self.epoch = 1
        self.revoked = False
    def permits(self, measurement: ALFMeasurement) -> bool:
        observed = {name: config for name, config, _ in measurement.components}
        with self._lock:
            return not self.revoked and observed == self.approved
    def revoke(self) -> None:
        with self._lock:
            self.revoked = True
            self.epoch += 1
    def advance_epoch(self) -> None:
        with self._lock:
            self.epoch += 1


@dataclass(frozen=True)
class ValidationReceipt:
    receipt_id: str
    alf_i: str
    alf_e: str
    alf_o: str
    policy_epoch: int
    sink: str
    expires_at: int
    mac: str
    def fields(self) -> dict:
        return {"receipt_id": self.receipt_id, "alf_i": self.alf_i,
                "alf_e": self.alf_e, "alf_o": self.alf_o,
                "policy_epoch": self.policy_epoch, "sink": self.sink,
                "expires_at": self.expires_at}


@dataclass(frozen=True)
class FinalityEnablement:
    receipt_id: str
    operation_commitment: str
    sink: str
    epoch: int
    mac: str
    def fields(self) -> dict:
        return {"receipt_id": self.receipt_id,
                "operation_commitment": self.operation_commitment,
                "sink": self.sink, "epoch": self.epoch}


class Validator:
    def __init__(self, controller: ActivationController, registry: ApprovalRegistry,
                 receipt_key: bytes, enablement_key: bytes):
        self.controller = controller
        self.registry = registry
        self._receipt_key = receipt_key
        self._enablement_key = enablement_key
        self._sequence = 0
    def validate(self, op: Operation, ttl: int = 60, now: int | None = None):
        if ttl <= 0:
            raise Denied("invalid TTL")
        now = int(time.time()) if now is None else now
        measurement = self.controller.measure()
        if not self.registry.permits(measurement):
            raise Denied("configuration is not approved")
        self._sequence += 1
        fields = dict(receipt_id=f"receipt-{self._sequence}", alf_i=measurement.alf_i,
                      alf_e=measurement.alf_e, alf_o=op.commitment,
                      policy_epoch=self.registry.epoch, sink=op.sink,
                      expires_at=now + ttl)
        receipt = ValidationReceipt(**fields, mac=signature(self._receipt_key, fields))
        enable_fields = dict(receipt_id=receipt.receipt_id,
                             operation_commitment=op.commitment, sink=op.sink,
                             epoch=self.registry.epoch)
        enablement = FinalityEnablement(**enable_fields,
                                       mac=signature(self._enablement_key, enable_fields))
        return receipt, enablement


class FinalitySink:
    """Single-process atomic consumption. The sink reconstructs descriptor from op argument."""
    def __init__(self, controller: ActivationController, registry: ApprovalRegistry,
                 receipt_key: bytes, enablement_key: bytes, sink_name="feed-gateway"):
        self.controller = controller
        self.registry = registry
        self._receipt_key = receipt_key
        self._enablement_key = enablement_key
        self.name = sink_name
        self._consumed: set[str] = set()
        self._lock = threading.RLock()
    def release(self, actual_pending: Operation, receipt: ValidationReceipt,
                enablement: FinalityEnablement | None, now: int | None = None) -> str:
        now = int(time.time()) if now is None else now
        with self._lock:
            if enablement is None:
                raise Denied("missing enablement")
            if not hmac.compare_digest(receipt.mac, signature(self._receipt_key, receipt.fields())):
                raise Denied("invalid receipt authentication")
            if not hmac.compare_digest(enablement.mac, signature(self._enablement_key, enablement.fields())):
                raise Denied("invalid enablement authentication")
            if receipt.sink != self.name or enablement.sink != self.name or actual_pending.sink != self.name:
                raise Denied("wrong sink")
            if receipt.receipt_id != enablement.receipt_id:
                raise Denied("receipt/enablement mismatch")
            if receipt.alf_o != actual_pending.commitment or enablement.operation_commitment != actual_pending.commitment:
                raise Denied("actual operation differs from authorized pending operation")
            if now > receipt.expires_at:
                raise Denied("receipt expired")
            if self.registry.revoked or receipt.policy_epoch != self.registry.epoch or enablement.epoch != self.registry.epoch:
                raise Denied("revoked or stale policy epoch")
            current = self.controller.measure()
            if current.alf_e != receipt.alf_e or current.alf_i != receipt.alf_i:
                raise Denied("activation/configuration hot-swap or generation mismatch")
            if not self.registry.permits(current):
                raise Denied("current configuration not approved")
            if receipt.receipt_id in self._consumed:
                raise Denied("single-use enablement already consumed")
            self._consumed.add(receipt.receipt_id)
            return f"RELEASED:{actual_pending.operation_id}"
