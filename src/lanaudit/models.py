"""Data models shared across the scanner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Risk severity. Integer values allow simple sorting and comparison."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class Finding:
    """A potential security issue observed on a host."""

    rule_id: str
    severity: Severity
    title: str
    detail: str
    port: int | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name
        return data


@dataclass
class Service:
    """An open TCP port and whatever we learned about it."""

    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    banner: str = ""
    tls: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Host:
    """A device discovered on the network."""

    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    discovered_by: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        """A simple 0-100 score: weighted sum of findings, capped at 100."""
        weights = {
            Severity.INFO: 0,
            Severity.LOW: 5,
            Severity.MEDIUM: 15,
            Severity.HIGH: 30,
            Severity.CRITICAL: 50,
        }
        return min(100, sum(weights[f.severity] for f in self.findings))

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "discovered_by": self.discovered_by,
            "risk_score": self.risk_score,
            "max_severity": self.max_severity.name,
            "services": [s.to_dict() for s in self.services],
            "findings": [f.to_dict() for f in self.findings],
        }
