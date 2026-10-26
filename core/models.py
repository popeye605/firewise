"""Typed, normalized models for firewall rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import ipaddress

IPAddressNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class Action(str, Enum):
    """Traffic decision made when a rule matches."""

    PERMIT = "permit"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class PortRange:
    """Inclusive destination-port interval."""

    start: int
    end: int

    def __post_init__(self) -> None:
        """Reject invalid ports and reversed intervals."""
        if not 0 <= self.start <= 65535:
            raise ValueError("Port start must be between 0 and 65535.")
        if not 0 <= self.end <= 65535:
            raise ValueError("Port end must be between 0 and 65535.")
        if self.start > self.end:
            raise ValueError("Port range start cannot exceed its end.")


@dataclass(frozen=True, slots=True)
class ServiceMatch:
    """Protocol and optional destination-port constraints."""

    protocol: str
    ports: tuple[PortRange, ...] = ()

    def __post_init__(self) -> None:
        """Normalize protocol spelling and validate the service."""
        normalized = self.protocol.strip().lower()
        if not normalized:
            raise ValueError("Service protocol cannot be empty.")
        object.__setattr__(self, "protocol", normalized)
        if normalized == "any" and self.ports:
            raise ValueError("An any-protocol service cannot specify ports.")


@dataclass(frozen=True, slots=True)
class Rule:
    """A normalized, first-match firewall rule."""

    id: str
    src_zone: str
    dst_zone: str
    src_networks: tuple[IPAddressNetwork, ...]
    dst_networks: tuple[IPAddressNetwork, ...]
    service: ServiceMatch
    action: Action
    log: bool
    not_analyzed: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate required identifiers and address constraints."""
        for field_name in ("id", "src_zone", "dst_zone"):
            value = getattr(self, field_name)
            if not value.strip():
                raise ValueError(f"{field_name} cannot be empty.")
            object.__setattr__(self, field_name, value.strip())
        if not self.src_networks:
            raise ValueError("A rule must contain at least one source network.")
        if not self.dst_networks:
            raise ValueError("A rule must contain at least one destination network.")

