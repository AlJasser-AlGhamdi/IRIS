"""Security-response-header analysis (Stage 3, Tier-1). Pure + fixture-testable.

**Absence contract.** A header is reported missing only from a response the scanner
actually received. A fetch that never completed (timeout, refused connection, TLS
failure) is an indeterminate read and yields no header findings at all, so a network
failure can never surface as a missing header. The gate lives at the call site, in
:func:`p2c.scanning.httpx_probe.checks_for_probe`, because that is where the evidence
of a received response (the status line) is available.
"""

from __future__ import annotations

import re

from p2c.scanning.catalog import CheckId

# Header (lowercased) -> the check raised when it is ABSENT.
#
# ``permissions-policy`` detector contract. *Observable*: the response header set. *Positive*: no
# ``Permissions-Policy`` header in a response that was received. *Negative*: the header is present,
# whatever its directives, because the control asks that the policy be declared, not that any
# particular feature be disabled. *Inconclusive*: no response, handled at the call site in
# ``httpx_probe.checks_for_probe`` like the other five. *Evidence*: the received header names.
_SECURITY_HEADERS: dict[str, CheckId] = {
    "strict-transport-security": CheckId.MISSING_HSTS,
    "content-security-policy": CheckId.MISSING_CSP,
    "x-frame-options": CheckId.MISSING_X_FRAME_OPTIONS,
    "x-content-type-options": CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
    "referrer-policy": CheckId.MISSING_REFERRER_POLICY,
    "permissions-policy": CheckId.MISSING_PERMISSIONS_POLICY,
}


def analyze_security_headers(headers: dict[str, str]) -> list[CheckId]:
    """Return the ``MISSING_*`` checks for absent security headers (case-insensitive).

    Precondition: ``headers`` are those of a response that was actually received. Callers
    must not invoke this for a failed fetch (see the module docstring); an empty mapping
    here means "the response carried no security headers", not "the fetch failed".
    """
    # A header sent with no value sets nothing, so it counts as absent.
    values = {name.lower(): value for name, value in headers.items() if value.strip()}
    present = set(values)
    if "frame-ancestors" in values.get("content-security-policy", "").lower():
        present.add("x-frame-options")  # CSP frame-ancestors supersedes X-Frame-Options (and is our advice)
    hsts = _MAX_AGE.search(values.get("strict-transport-security", ""))
    if "strict-transport-security" in present and not (hsts and int(hsts.group(1)) > 0):
        present.discard("strict-transport-security")  # max-age=0, or none, tells a browser to drop HSTS
    return [check for header, check in _SECURITY_HEADERS.items() if header not in present]


_MAX_AGE = re.compile(r"(?i)max-age\s*=\s*\"?(\d{1,12})")
