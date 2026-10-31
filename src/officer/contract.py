"""The typed contract between the agent and the private lab worker.

The worker runs the live scanner and the ownership gate (withheld from this repository, see NOTICE). It
returns only enums, integers, hashes and in-scope hostnames; text a target controls (banners, page titles,
TXT records, service replies) never crosses, so it cannot reach the model.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from p2c.scanning.catalog import CheckId

_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
# DNS record names may carry underscore labels (e.g. "_challenge.example.test"); hosts may not.
_DNS_NAME = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


class Group(StrEnum):
    """Scan source groups; a re-scan reads one or more of them again."""

    DNS = "dns"  # email authentication, DNSSEC, zone transfer, DDoS provider (apex)
    WEB = "web"  # headers, cookies, redirect, paths, banners
    TLS = "tls"  # certificate and protocol reads
    PORTS = "ports"  # TCP connect over the flagged ports, then service greetings


class FixId(StrEnum):
    """Every change the agent may apply in the lab. Anything else is refused by both sides."""

    PUBLISH_SPF = "publish_spf"
    SET_DMARC_REJECT = "set_dmarc_reject"
    CLOSE_DB_PORT = "close_db_port"  # 3306
    CLOSE_CACHE_PORT = "close_cache_port"  # 6379
    CLOSE_PRINTER_PORTS = "close_printer_ports"  # 631, 515
    CLOSE_FTP_PORT = "close_ftp_port"  # 21
    ENABLE_HTTPS_REDIRECT = "enable_https_redirect"


class StopReason(StrEnum):
    OWNERSHIP_LOST = "ownership_lost"  # the TXT record vanished mid-scan
    WINDOW_CLOSED = "window_closed"
    WORKER_ERROR = "worker_error"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _check_ids(values: list[str]) -> list[str]:
    known = {c.value for c in CheckId}
    bad = [v for v in values if v not in known]
    if bad:
        raise ValueError(f"unknown detector ids: {bad}")
    return sorted(set(values))


class ChallengeOut(Strict):
    challenge_id: str = Field(pattern=r"^[A-Za-z0-9_-]{8,64}$")
    record_name: str
    token: str = Field(pattern=r"^[A-Za-z0-9_-]{16,128}$")

    @field_validator("record_name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _DNS_NAME.match(value):
            raise ValueError("record name is not a DNS name")
        return value


class VerifyOut(Strict):
    verified: bool
    verification_id: str | None = None


class GroupResult(Strict):
    group: Group
    host: str
    findings: list[str]
    unread: list[str]

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        if not _HOST.match(value):
            raise ValueError("host is not a hostname")
        return value

    @field_validator("findings", "unread")
    @classmethod
    def _ids(cls, values: list[str]) -> list[str]:
        return _check_ids(values)


class ScanOut(Strict):
    scan_id: str = Field(pattern=r"^[A-Za-z0-9_-]{8,64}$")
    results: list[GroupResult]
    stopped: bool = False
    stop_reason: StopReason | None = None
    audit_head: str
    duration_ms: int = Field(ge=0)

    @field_validator("audit_head")
    @classmethod
    def _hex(cls, value: str) -> str:
        if not _HEX.match(value):
            raise ValueError("audit head is not a sha256 hex digest")
        return value


class FixOut(Strict):
    fix_id: FixId
    applied: bool


class ScanIn(Strict):
    apex: str
    hosts: list[str]
    verification_ids: list[str]
    groups: list[Group]


class EstateIn(Strict):
    """Reset the lab to the demo estate or to a seeded estate (evaluation only)."""

    estate: str = Field(pattern=r"^(demo|seed-[0-9]{1,6})$")


class EstateOut(Strict):
    estate: str
    apex: str
    hosts: list[str]
