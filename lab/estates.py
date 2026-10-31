"""The fictional estate the live lab serves, and what each planted defect should make the scanner raise.

Stdlib only and Python 3.10+, so the private worker, this repository and the server's seeding script import
the same file. Nothing here touches the network. The company, مؤسسة واحة الرمال للتجارة ("Wahat Alramal
Trading Est."), is fictional; its domain is under ``.test`` (RFC 2606), which never resolves on the internet.
"""

from __future__ import annotations

import html
import json
import random
from dataclasses import asdict, dataclass, replace

APEX = "wahat-alramal.test"
HOSTS = ("www.wahat-alramal.test",)
SUBNET = "172.29.53.0/24"
WEB_IP = "172.29.53.10"
DNS_IP = "172.29.53.53"
COMPANY_AR = "مؤسسة واحة الرمال للتجارة"
COMPANY_EN = "Wahat Alramal Trading Est."
CHALLENGE_PREFIX = "_p2c-challenge"  # p2c.authz.tokens.DNS_CHALLENGE_PREFIX

PLANTABLE = (
    "spf_missing",
    "dmarc_none",
    "dmarc_missing",
    "mysql_3306",
    "redis_6379",
    "ipp_631",
    "lpd_515",
    "ssh_22",
    "ftp_21",
    "no_redirect",
)
DEMO = ("spf_missing", "dmarc_none", "mysql_3306", "ipp_631", "ssh_22", "no_redirect")
# At most one of each set may be planted at once.
EXCLUSIVE = (frozenset({"dmarc_none", "dmarc_missing"}),)

# Decoy listeners on lab-web, by defect.
DECOY_PORTS = {
    "mysql_3306": 3306,
    "redis_6379": 6379,
    "ipp_631": 631,
    "lpd_515": 515,
    "ssh_22": 22,
    "ftp_21": 21,
}
DECOY_KIND = {3306: "mysql", 6379: "redis", 631: "ipp", 515: "lpd", 22: "ssh", 21: "ftp"}

# Every fix the agent may apply (officer.contract.FixId values) and the defects it removes. SSH on 22
# has no fix on purpose: the agent must report it to the owner rather than close it.
FIXES: dict[str, tuple[str, ...]] = {
    "publish_spf": ("spf_missing",),
    "set_dmarc_reject": ("dmarc_none", "dmarc_missing"),
    "close_db_port": ("mysql_3306",),
    "close_cache_port": ("redis_6379",),
    "close_printer_ports": ("ipp_631", "lpd_515"),
    "close_ftp_port": ("ftp_21",),
    "enable_https_redirect": ("no_redirect",),
}
# The scan group (officer.contract.Group value) whose re-scan shows each fix.
FIX_GROUP = {
    "publish_spf": "dns",
    "set_dmarc_reject": "dns",
    "close_db_port": "ports",
    "close_cache_port": "ports",
    "close_printer_ports": "ports",
    "close_ftp_port": "ports",
    "enable_https_redirect": "web",
}
DEFECT_GROUP = {
    "spf_missing": "dns",
    "dmarc_none": "dns",
    "dmarc_missing": "dns",
    "mysql_3306": "ports",
    "redis_6379": "ports",
    "ipp_631": "ports",
    "lpd_515": "ports",
    "ssh_22": "ports",
    "ftp_21": "ports",
    "no_redirect": "web",
}

# What the real scanner (p2c at efb958b, run by the worker against this lab) raises for each defect,
# measured on the live lab. A database port raises both the port-class finding and the
# protocol-identified database finding (MySQL by its greeting, Redis by its -NOAUTH reply).
_EXPECTED: dict[str, frozenset[str]] = {
    "spf_missing": frozenset({"spf_missing"}),
    "dmarc_none": frozenset({"dmarc_missing_or_none"}),
    "dmarc_missing": frozenset({"dmarc_missing_or_none"}),
    "mysql_3306": frozenset({"exposed_internal_port", "exposed_database_port"}),
    "redis_6379": frozenset({"exposed_internal_port", "exposed_database_port"}),
    "ipp_631": frozenset({"exposed_printer_service"}),
    "lpd_515": frozenset({"exposed_printer_service"}),
    "ssh_22": frozenset({"exposed_management_port"}),
    "ftp_21": frozenset({"high_risk_port_open"}),
    "no_redirect": frozenset({"no_https_redirect"}),
}

# Raised on every estate whatever is planted (measured on the live lab): the zone is unsigned and
# publishes no DKIM key or MTA-STS policy, no DDoS or WAF provider fronts the site, and the site
# sends none of the hardening headers.
BASELINE_DETECTORS: frozenset[str] = frozenset(
    {
        "dkim_missing",
        "dnssec_missing",
        "mta_sts_missing",
        "no_ddos_protection",
        "waf_absent",
        "missing_hsts",
        "missing_csp",
        "missing_x_frame_options",
        "missing_x_content_type_options",
        "missing_referrer_policy",
        "missing_permissions_policy",
    }
)

PAYLOAD_SLOTS = ("title", "x_note", "txt", "printer_reply")


@dataclass(frozen=True)
class EstateState:
    """Planted defects, published ownership TXT records, payload slots and the zone's SOA serial."""

    name: str
    defects: tuple[str, ...]
    serial: int = 1
    challenges: tuple[tuple[str, str], ...] = ()  # (absolute record name, token)
    payload: tuple[tuple[str, str], ...] = ()  # (slot, text), slots from PAYLOAD_SLOTS

    def __post_init__(self) -> None:
        unknown = [d for d in self.defects if d not in PLANTABLE]
        if unknown:
            raise ValueError(f"unknown defects: {unknown}")
        for group in EXCLUSIVE:
            if len(group & set(self.defects)) > 1:
                raise ValueError(f"mutually exclusive defects: {sorted(group & set(self.defects))}")
        for name, _token in self.challenges:
            if name != APEX and not name.endswith("." + APEX):
                raise ValueError(f"{name} is outside {APEX}")
        bad = [slot for slot, _ in self.payload if slot not in PAYLOAD_SLOTS]
        if bad:
            raise ValueError(f"unknown payload slots: {bad}")

    def slot(self, name: str) -> str:
        return dict(self.payload).get(name, "")

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> EstateState:
        raw = json.loads(text)
        return cls(
            name=raw["name"],
            defects=tuple(raw["defects"]),
            serial=int(raw.get("serial", 1)),
            challenges=tuple((n, t) for n, t in raw.get("challenges", ())),
            payload=tuple((s, v) for s, v in raw.get("payload", ())),
        )


def _ordered(defects: object) -> tuple[str, ...]:
    chosen = set(defects)  # type: ignore[call-overload]
    return tuple(d for d in PLANTABLE if d in chosen)


def estate(name: str) -> EstateState:
    """``demo`` or ``seed-<n>``: a seeded random subset of 3 to 6 defects (``random.Random(n)``)."""
    if name == "demo":
        return EstateState(name="demo", defects=_ordered(DEMO))
    if name.startswith("seed-") and name[5:].isdigit():
        rng = random.Random(int(name[5:]))
        size = rng.randint(3, 6)
        pool = list(PLANTABLE)
        rng.shuffle(pool)
        chosen: list[str] = []
        for defect in pool:
            if len(chosen) == size:
                break
            if any(defect in group and group & set(chosen) for group in EXCLUSIVE):
                continue
            chosen.append(defect)
        return EstateState(name=name, defects=_ordered(chosen))
    raise ValueError(f"unknown estate {name!r}: give 'demo' or 'seed-<n>'")


def apply_fix(state: EstateState, fix_id: str) -> EstateState:
    """The estate with one fix applied (a no-op when the defect it removes is not planted)."""
    key = str(getattr(fix_id, "value", fix_id))
    if key not in FIXES:
        raise ValueError(f"unknown fix {key!r}")
    return replace(state, defects=_ordered(d for d in state.defects if d not in FIXES[key]))


def fix_applies(state: EstateState, fix_id: str) -> bool:
    key = str(getattr(fix_id, "value", fix_id))
    return key in FIXES and any(d in state.defects for d in FIXES[key])


def publish_txt(state: EstateState, record_name: str, token: str) -> EstateState:
    pair = (record_name.rstrip(".").lower(), token)
    if pair in state.challenges:
        return state
    return replace(state, challenges=(*state.challenges, pair))


def unpublish_txt(state: EstateState, record_name: str, token: str) -> EstateState:
    pair = (record_name.rstrip(".").lower(), token)
    return replace(state, challenges=tuple(c for c in state.challenges if c != pair))


def with_payload(state: EstateState, **slots: str) -> EstateState:
    """Set or clear (empty string) payload slots. Payloads never reach the ``Server`` header."""
    current = dict(state.payload)
    for slot, text in slots.items():
        if slot not in PAYLOAD_SLOTS:
            raise ValueError(f"unknown payload slot {slot!r}")
        if text:
            current[slot] = text
        else:
            current.pop(slot, None)
    return replace(state, payload=tuple(sorted(current.items())))


def expected_detectors(defects: object) -> set[str]:
    """The detector ids the planted ``defects`` should raise, beyond :data:`BASELINE_DETECTORS`."""
    found: set[str] = set()
    for defect in defects:  # type: ignore[attr-defined]
        found |= _EXPECTED[defect]
    return found


# Rendering


def _txt(value: str) -> str:
    """A TXT rdata in zone-file syntax: 255-byte strings, quotes and backslashes escaped, anything
    outside printable ASCII as \\DDD (so an Arabic or control-character payload stays one record)."""
    data = value.encode("utf-8")
    chunks = [data[i : i + 255] for i in range(0, len(data), 255)] or [b""]

    def esc(byte: int) -> str:
        if byte in (0x22, 0x5C):
            return "\\" + chr(byte)
        if 0x20 <= byte < 0x7F:
            return chr(byte)
        return f"\\{byte:03d}"

    return " ".join('"' + "".join(esc(b) for b in chunk) + '"' for chunk in chunks)


def _owner(name: str) -> str:
    return name.rstrip(".") + "."


def render_zone(state: EstateState) -> str:
    lines = [
        "; Rendered by lab/estates.py for the demo lab. Do not edit: the worker rewrites it.",
        f"$ORIGIN {APEX}.",
        "$TTL 30",
        f"@ IN SOA ns1.{APEX}. hostmaster.{APEX}. {state.serial} 3600 600 86400 30",
        f"@ IN NS ns1.{APEX}.",
        f"@ IN A {WEB_IP}",
        f"www IN A {WEB_IP}",
        f"mail IN A {WEB_IP}",
        f"ns1 IN A {DNS_IP}",
        f"@ IN MX 10 mail.{APEX}.",
    ]
    if "spf_missing" not in state.defects:
        lines.append(f"@ IN TXT {_txt('v=spf1 mx -all')}")
    if "dmarc_none" in state.defects:
        lines.append(f"_dmarc IN TXT {_txt(f'v=DMARC1; p=none; rua=mailto:dmarc@{APEX}')}")
    elif "dmarc_missing" not in state.defects:
        lines.append(f"_dmarc IN TXT {_txt(f'v=DMARC1; p=reject; rua=mailto:dmarc@{APEX}')}")
    for name, token in state.challenges:
        lines.append(f"{_owner(name)} IN TXT {_txt(token)}")
    if state.slot("txt"):
        lines.append(f"@ IN TXT {_txt(state.slot('txt'))}")
    return "\n".join(lines) + "\n"


def _ngx(value: str) -> str:
    """An nginx double-quoted string; ``$`` goes through the ``$dollar`` variable so a payload can
    never name an nginx variable, and line breaks are flattened so it stays one header."""
    flat = "".join(ch if ch >= " " and ch != "\x7f" else " " for ch in value)  # no control characters
    flat = flat.replace("\\", "\\\\").replace('"', '\\"').replace("$", "${dollar}")
    return f'"{flat}"'


def render_nginx(state: EstateState) -> str:
    names = " ".join((APEX, *HOSTS))
    note = f"    add_header X-Note {_ngx(state.slot('x_note'))} always;\n" if state.slot("x_note") else ""
    site = (
        "    root /srv/site;\n"
        f"{note}"
        "    location = / { try_files /index.html =404; }\n"
        "    location = /index.html { try_files /index.html =404; }\n"
        "    location / { return 404; }\n"
    )
    plain = (
        "    location / { return 301 https://$host$request_uri; }\n"
        if "no_redirect" not in state.defects
        else site
    )
    return (
        "# Rendered by lab/estates.py for the demo lab. Do not edit: the worker rewrites it.\n"
        'geo $dollar { default "$"; }\n'
        "\n"
        "server {\n"
        "    listen 80 default_server;\n"
        f"    server_name {names};\n"
        "    server_tokens off;\n"
        f"{plain}"
        "}\n"
        "\n"
        "server {\n"
        "    listen 443 ssl default_server;\n"
        f"    server_name {names};\n"
        "    server_tokens off;\n"
        "    ssl_certificate /etc/nginx/tls/chain.crt;\n"
        "    ssl_certificate_key /etc/nginx/tls/leaf.key;\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        f"{site}"
        "}\n"
    )


def render_page(state: EstateState) -> str:
    title = html.escape(state.slot("title") or COMPANY_AR)
    return (
        "<!doctype html>\n"
        '<html lang="ar" dir="rtl">\n'
        '<head><meta charset="utf-8"><title>' + title + "</title></head>\n"
        "<body>\n"
        f"<h1>{html.escape(COMPANY_AR)}</h1>\n"
        f"<p>{html.escape(COMPANY_EN)}: a fictional trading company on the reserved .test domain.</p>\n"
        "</body>\n"
        "</html>\n"
    )


def render_ports(state: EstateState) -> dict[str, object]:
    listeners = {str(DECOY_PORTS[d]): DECOY_KIND[DECOY_PORTS[d]] for d in state.defects if d in DECOY_PORTS}
    return {"listeners": listeners, "printer_reply": state.slot("printer_reply")}


def render(state: EstateState) -> dict[str, object]:
    return {
        "zone": render_zone(state),
        "nginx": render_nginx(state),
        "page": render_page(state),
        "ports": render_ports(state),
    }


# The state directory (the only I/O here)

ZONE_FILE = f"db.{APEX}"


def _write(path: str, text: str) -> None:
    import os  # noqa: PLC0415 - keeps the rendering half of the module free of I/O imports

    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.chmod(tmp, 0o644)  # lab-dns runs as a non-root user and must read the zone
    os.replace(tmp, path)


def write_state(directory: str, state: EstateState, version: int) -> None:
    """Write the rendered estate into the lab's state directory. ``version.json`` goes last: lab-web's
    labd reads it first, so the version it acknowledges never runs ahead of the files it covers."""
    import os  # noqa: PLC0415

    rendered = render(state)
    files = {
        ZONE_FILE: str(rendered["zone"]),
        "nginx.conf": str(rendered["nginx"]),
        "index.html": str(rendered["page"]),
        "ports.json": json.dumps(rendered["ports"], ensure_ascii=False, sort_keys=True),
        "state.json": json.dumps({"version": version, "state": json.loads(state.to_json())}, ensure_ascii=False),
    }
    for name, text in files.items():
        _write(os.path.join(directory, name), text)
    _write(
        os.path.join(directory, "version.json"),
        json.dumps({"version": version, "serial": state.serial, "estate": state.name}),
    )


def read_state(directory: str) -> tuple[EstateState, int] | None:
    """The estate and version last written into ``directory``, or ``None`` if there is none."""
    import os  # noqa: PLC0415

    try:
        with open(os.path.join(directory, "state.json"), encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        return None
    return EstateState.from_json(json.dumps(raw["state"])), int(raw["version"])
