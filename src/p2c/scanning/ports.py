"""Port findings from naabu output (Stage 3, Tier-1). Pinned naabu v2.6.1 (ADR-0004).

**Detector contracts** (``exposed_internal_port``, ``exposed_management_port``,
``high_risk_port_open``, ``exposed_printer_service``). Each class is read from the port number alone,
not the protocol.

    *Observable*: a TCP connection to every port of the class, on each address the host resolves to.
    *Positive*: a port of the class completes the handshake. SMTP (25) on the domain's own mail
    exchangers is their service, not a finding. *Negative*: the host answered, and no port of the class
    completed a handshake. *Inconclusive*: no port of the class was probed (a narrowed list, or every one
    blocked at the scanner), the host answered on no port, or a port no service is assigned answered,
    so something on the path completes every handshake. *Evidence*: the port and the addresses it is
    open on.
"""

from __future__ import annotations

import json

from p2c.scanning.catalog import CheckId

# Internal/data-tier services that should never face the internet directly.
_INTERNAL_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017}
# Remote-management services (SSH/RDP/VNC/WinRM).
_MANAGEMENT_PORTS = {22, 3389, 5900, 5985, 5986}
# Legacy/plaintext/high-risk services. SMTP (25) is one only off the mail exchanger: the pilot runner
# exempts the domain's own MX addresses (p2c.pilot.runner).
_HIGH_RISK_PORTS = {21, 23, 25, 111, 135, 139, 445, 512, 513, 514}
# Print services by their assigned ports (LPD, IPP); number-only like the classes above, not probed by
# protocol. Raw printing on 9100 is not read (2026-10-21): it is also the default port of the Prometheus
# node exporter, so the number alone does not show a print service.
_PRINTER_PORTS = {515, 631}


def parse_naabu(output: str) -> list[tuple[str, int]]:
    """Parse naabu ``-json`` JSONL into ``(host, port)`` pairs."""
    results: list[tuple[str, int]] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        host = obj.get("host") or obj.get("ip")
        port = obj.get("port")
        if isinstance(host, str) and isinstance(port, int):
            results.append((host, port))
    return results


def classify_port(port: int) -> CheckId | None:
    """Map an open port to a Tier-1 check, or ``None`` if it is not flagged."""
    if port in _INTERNAL_PORTS:
        return CheckId.EXPOSED_INTERNAL_PORT
    if port in _MANAGEMENT_PORTS:
        return CheckId.EXPOSED_MANAGEMENT_PORT
    if port in _HIGH_RISK_PORTS:
        return CheckId.HIGH_RISK_PORT_OPEN
    if port in _PRINTER_PORTS:
        return CheckId.EXPOSED_PRINTER_SERVICE
    return None


# Every port a flagged class covers, for a scanner that probes them itself instead of reading naabu.
PROBED_PORTS: tuple[int, ...] = tuple(
    sorted(_INTERNAL_PORTS | _MANAGEMENT_PORTS | _HIGH_RISK_PORTS | _PRINTER_PORTS)
)
