"""TLS inspection (Stage 3, Tier-1) via the stdlib ``ssl`` module (ADR-0004).

In-process (so it passes the sovereignty egress guard), no AGPL ``sslyze``. The
pure :func:`evaluate_tls` is unit-tested; :class:`TlsInspector` does the socket
handshake and is exercised against the ``test-target`` in integration.

**Absence contract.** :func:`evaluate_tls` flags only what the handshake actually read: an
unread version, cipher, expiry date, issuer relation or key size produces no finding. A
handshake that fails outright raises out of :meth:`TlsInspector.inspect` rather than returning
a default posture, so the caller records an unreadable endpoint instead of a fabricated
legacy-TLS or expired-cert finding (``ScanEngine`` isolates the source and reports the error).
Every certificate field is ``None`` until it is parsed, which is the inconclusive state: unknown,
never "absent".

**Detector contracts.**

``expired_certificate``
    *Observable*: the certificate's ``notValidBefore`` and ``notValidAfter``. *Positive*: now falls
    outside that window, either because the certificate has expired or because it is not yet valid,
    which is what the catalogue row is titled. *Negative*: now falls inside it. *Inconclusive*: the
    certificate did not parse. *Evidence*: both parsed bounds.
    Fixed 2026-08-30, and it had never worked: ``getpeercert()`` returns an empty
    dict under ``CERT_NONE``, which this module sets in order to observe rather than enforce, so
    the live path read ``notAfter`` from ``{}`` and the check could not fire. Only the pure
    function was tested, with a hand-built ``TlsInfo``, so no test saw it. The DER is now parsed
    from ``getpeercert(binary_form=True)``.

``self_signed_certificate``
    *Observable*: the certificate's issuer, subject and signature. *Positive*: issuer equals
    subject **and** the signature verifies under the certificate's own public key. *Negative*:
    either test fails. *Inconclusive*: the certificate did not parse, or the signature algorithm
    is unsupported. *Evidence*: the issuer and subject RFC 4514 strings. Deliberately not "the
    local trust store rejected it": that fires on every private and enterprise CA, which is a
    different finding.

``legacy_tls_version``
    *Observable*: the protocol of the first handshake, and a second handshake whose highest offered
    version is TLS 1.1. *Positive*: either negotiated SSL 3.0, TLS 1.0 or TLS 1.1; a modern client
    gets the best version a server offers, so the capped probe is what shows a server that also
    accepts a legacy one. *Negative*: the server refused the capped probe. *Inconclusive*: the probe
    got no answer. A server that refuses every modern offer is read through the capped handshake
    instead of failing, so a legacy-only endpoint is reported rather than left unread.

``weak_tls_cipher``
    *Observable*: the negotiated suite, and a handshake offering only weak suites. *Positive*: a weak
    suite was negotiated either way. *Negative*: the server refused the weak-only offer.
    *Inconclusive*: no answer, or a scanner library that can offer no weak suite at all. **Declared
    blind spot**: current TLS libraries no longer compile in RC4, DES, 3DES or export suites, so the
    probe can offer only NULL, anonymous and MD5 suites, and a server that accepts 3DES or RC4 on
    request reads clean here.

``weak_certificate_key``
    *Observable*: the subject public key. *Positive*: RSA below 3072 bits, any DSA key, or an
    elliptic curve outside P-256, P-384, P-521 and the three Brainpool curves. *Negative*: RSA at or
    above 3072 bits, an accepted curve, or an Ed25519 or Ed448 key. *Inconclusive*: the key did not
    parse or is of an algorithm the threshold does not cover. *Evidence*: the algorithm and size. The
    line is the NCA's National Cryptographic Standards for intermediate and end-user certificates
    (NCS-1:2020, section 5.1: RSA of at least 3072 bits, or ECC on the listed curves, Curve25519 and
    Curve448 among them), so a 2048-bit RSA key, which the CA/Browser Forum still accepts, is outside
    the standard the linked control names. No signature algorithm is tested.
"""

from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from p2c.scanning.catalog import CheckId

_LEGACY_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
_LEGACY_PROBE = ("TLSv1_1", "DEFAULT:@SECLEVEL=0")  # the highest version offered, and the suites
# Every weak family is named; the library silently drops the ones it no longer compiles in.
_WEAK_PROBE = ("TLSv1_2", "NULL:aNULL:MD5:RC4:DES:3DES:EXPORT:@SECLEVEL=0")
# Errors our own library raises before the server is asked anything: a build without TLS 1.1 or
# without any of the offered suites. They leave the probe unread, never a server refusal.
# Refusals our own library raises (it could not make the offer, or would not continue with a server
# that lacks secure renegotiation): nothing was asked of the server, so they read as unread.
_LOCAL_LIMITS = frozenset(
    {"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "UNSAFE_LEGACY_RENEGOTIATION_DISABLED"}
)
_WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON", "RC2")

# The NCA's National Cryptographic Standards (NCS-1:2020, section 5.1) for intermediate and end-user
# certificates: RSA of at least 3072 bits, or ECC on P-256, P-384, P-521, Curve25519, Curve448 or the
# Brainpool curves. DSA is not among the accepted algorithms.
_MIN_RSA_BITS = 3072
_APPROVED_CURVES = frozenset(
    {"secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"}
)


@dataclass(frozen=True)
class TlsInfo:
    """Observed TLS posture of an endpoint. ``None`` marks a field that was not read."""

    version: str
    cipher: str
    not_after: datetime | None = None
    not_before: datetime | None = None
    self_signed: bool | None = None
    key_algorithm: str | None = None
    key_bits: int | None = None
    curve: str | None = None
    issuer: str | None = None
    subject: str | None = None
    legacy_accepted: bool | None = None  # the capped probe's answer; None when it got none
    weak_accepted: bool | None = None  # the weak-suite probe's answer; None when it got none


def evaluate_tls(info: TlsInfo, *, now: datetime | None = None) -> list[CheckId]:
    """Map an observed :class:`TlsInfo` to Tier-1 TLS checks (pure).

    Every branch tests a value that was read: an empty version or cipher, or a ``None``
    expiry, is an unread field and raises nothing.
    """
    at = now or datetime.now(UTC)
    checks: list[CheckId] = []
    if info.version in _LEGACY_VERSIONS or info.legacy_accepted:
        checks.append(CheckId.LEGACY_TLS_VERSION)
    upper = info.cipher.upper()
    if any(marker in upper for marker in _WEAK_CIPHER_MARKERS) or info.weak_accepted:
        checks.append(CheckId.WEAK_TLS_CIPHER)
    if (info.not_after is not None and info.not_after < at) or (
        info.not_before is not None and info.not_before > at
    ):
        checks.append(CheckId.EXPIRED_CERTIFICATE)
    if info.self_signed:
        checks.append(CheckId.SELF_SIGNED_CERTIFICATE)
    if _key_is_weak(info):
        checks.append(CheckId.WEAK_CERTIFICATE_KEY)
    return checks


def _key_is_weak(info: TlsInfo) -> bool:
    """True only when the key was read and falls below the documented threshold."""
    if info.key_algorithm is None:
        return False
    if info.key_algorithm == "dsa":
        return True
    if info.key_algorithm == "rsa":
        return info.key_bits is not None and info.key_bits < _MIN_RSA_BITS
    if info.key_algorithm == "ec":
        return info.curve is not None and info.curve not in _APPROVED_CURVES
    return False


def _context(probe: tuple[str, str] | None = None) -> ssl.SSLContext:
    """An observing client context (no trust check); ``probe`` caps the version and sets the suites."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():  # offering a deprecated protocol is what the probe is for
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        if probe is not None:
            ctx.maximum_version = getattr(ssl.TLSVersion, probe[0])
    if probe is not None:
        ctx.set_ciphers(probe[1])
    return ctx


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> tuple[str, str, bytes | None]:
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        ctx.wrap_socket(sock, server_hostname=host) as tls_sock,
    ):
        cipher_tuple = tls_sock.cipher()
        return (
            tls_sock.version() or "",
            cipher_tuple[0] if cipher_tuple else "",
            tls_sock.getpeercert(binary_form=True),
        )


def _accepts(host: str, port: int, probe: tuple[str, str], timeout: float) -> bool | None:
    """Whether the server completes a handshake on this offer: False when it refuses, None unread."""
    try:
        ctx = _context(probe)
    except ssl.SSLError:
        return None  # the library can offer none of these suites: nothing was asked
    for _attempt in range(2):  # a dropped connection may be a rate limiter, not a refusal: once more
        try:
            _handshake(host, port, ctx, timeout)
        except ssl.SSLEOFError:
            continue
        except ssl.SSLError as exc:
            if getattr(exc, "reason", None) in _LOCAL_LIMITS:
                return None  # our library could not make the offer: nothing was asked of the server
            return False  # a TLS alert: the server refused the offer
        except OSError:
            return None
        return True
    return None  # dropped twice without an alert: unread, never a refusal


class TlsInspector:
    """Handshakes with an endpoint and reports its TLS posture, probing legacy and weak offers."""

    def inspect(self, host: str, port: int = 443, *, timeout: float = 10.0) -> TlsInfo:
        try:
            version, cipher, der = _handshake(host, port, _context(), timeout)
        except ssl.SSLError:
            # A server that refuses every modern offer may still speak a legacy protocol: read it that
            # way. If this fails too, the endpoint is unreadable and the error propagates.
            version, cipher, der = _handshake(host, port, _context(_LEGACY_PROBE), timeout)
        legacy = True if version in _LEGACY_VERSIONS else _accepts(host, port, _LEGACY_PROBE, timeout)
        weak = _accepts(host, port, _WEAK_PROBE, timeout)
        facts = _parse_certificate(der)
        return TlsInfo(
            version=version,
            cipher=cipher,
            not_after=facts.not_after,
            not_before=facts.not_before,
            self_signed=facts.self_signed,
            key_algorithm=facts.key_algorithm,
            key_bits=facts.key_bits,
            curve=facts.curve,
            issuer=facts.issuer,
            subject=facts.subject,
            legacy_accepted=legacy,
            weak_accepted=weak,
        )


@dataclass(frozen=True)
class _CertificateFacts:
    """What the peer certificate yielded. Every field is ``None`` until it is read."""

    not_after: datetime | None = None
    not_before: datetime | None = None
    self_signed: bool | None = None
    key_algorithm: str | None = None
    key_bits: int | None = None
    curve: str | None = None
    issuer: str | None = None
    subject: str | None = None


def _parse_certificate(der: bytes | None) -> _CertificateFacts:
    """Read expiry, issuer relation and key strength from the peer's DER certificate.

    Every field stays ``None``, the inconclusive state, when it cannot be read, so a
    certificate that does not parse yields no finding rather than a fabricated one.
    ``getpeercert()`` is not used: it returns an empty dict whenever the peer was not
    validated, and this inspector deliberately does not validate, so the dictionary form
    carries nothing.
    """
    if not der:
        return _CertificateFacts()
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return _CertificateFacts()
    algorithm, bits, curve = _public_key_strength(cert)
    return _CertificateFacts(
        not_after=cert.not_valid_after_utc,
        not_before=cert.not_valid_before_utc,
        self_signed=_is_self_signed(cert),
        key_algorithm=algorithm,
        key_bits=bits,
        curve=curve,
        issuer=cert.issuer.rfc4514_string(),
        subject=cert.subject.rfc4514_string(),
    )


def _is_self_signed(cert: x509.Certificate) -> bool | None:
    """Issuer equals subject *and* the signature verifies under the certificate's own key.

    The name test alone is not enough: a certificate can carry a matching issuer name without
    being signed by that key. Returning ``None`` for an unsupported algorithm keeps an
    unverifiable certificate out of the finding set instead of guessing from the names.
    """
    if cert.issuer != cert.subject:
        return False
    key = cert.public_key()
    digest = cert.signature_hash_algorithm
    try:
        if isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes)
        elif digest is None:
            return None
        elif isinstance(key, rsa.RSAPublicKey):
            # RSASSA-PSS as well as PKCS#1 v1.5: the library reads the padding from the certificate.
            cert.verify_directly_issued_by(cert)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(digest))
        else:
            return None
    except InvalidSignature:
        return False
    except (UnsupportedAlgorithm, TypeError, ValueError):
        return None
    return True


def _public_key_strength(cert: x509.Certificate) -> tuple[str | None, int | None, str | None]:
    """Algorithm, size and curve of the subject public key; all ``None`` if it did not parse."""
    try:
        key = cert.public_key()
    except (UnsupportedAlgorithm, ValueError):  # pragma: no cover - exotic key
        return None, None, None
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa", key.key_size, None
    if isinstance(key, dsa.DSAPublicKey):
        return "dsa", key.key_size, None
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ec", key.curve.key_size, key.curve.name
    if isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        return "eddsa", None, None
    return None, None, None
