"""SSRF guard for the crawler's two entry points (discover(), recon()).

Both fetch whatever URL they're given, server-side, with a real
browser — the exact shape of an SSRF vector if this is ever exposed
beyond a single trusted operator running it against targets they're
authorized to test. This blocks the classic internal-network targets:
loopback, RFC1918 private ranges, link-local (which includes the cloud
metadata endpoint 169.254.169.254), and other reserved ranges.

This resolves the hostname once at check time — it does not defend
against DNS rebinding (a domain that resolves safely here and then
returns a private IP when Playwright fetches it moments later). That
class of attack needs to be checked inside the browser's own
connection instead, which Playwright doesn't expose easily; noting the
gap rather than claiming full protection.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeUrlError(ValueError):
    """Raised when a target URL resolves to a blocked network range."""


def assert_safe_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeUrlError(f"Unsupported scheme: {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise UnsafeUrlError("URL has no hostname")

    try:
        # AF_UNSPEC covers both IPv4 and IPv6 records.
        resolved = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"Could not resolve hostname: {hostname!r}") from exc

    for ip_str in resolved:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local  # includes 169.254.169.254, the cloud metadata endpoint
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise UnsafeUrlError(
                f"{hostname!r} resolves to {ip_str}, which is in a blocked network range"
            )
