"""Google Threat Intelligence (GTI) integration UDFs for Tracecat.

This module provides GTI (formerly known as VirusTotal) API integration for
security automation workflows, including lookups for domains, file hashes,
IP addresses, URLs, and advanced threat intelligence features.

Requires a GTI API key configured as a Tracecat secret.
Configure the 'gti' secret in Tracecat UI with your API key.

API Reference: https://docs.virustotal.com/reference/overview
"""

import base64
from typing import Annotated, Any

import httpx
from pydantic import Field

from tracecat_registry import RegistrySecret, registry, secrets


# Define the secret schema for GTI API key
gti_secret = RegistrySecret(
    name="gti",
    keys=["GTI_API_KEY"],
)
"""GTI (Google Threat Intelligence) API key.

Configure the 'gti' secret in Tracecat with:
- GTI_API_KEY: Your GTI API key

Get your API key from: https://www.virustotal.com/gui/my-apikey
"""

GTI_BASE_URL = "https://www.virustotal.com/api/v3"


def _get_headers() -> dict[str, str]:
    """Build request headers with the GTI API key."""
    api_key = secrets.get("GTI_API_KEY")
    return {"x-apikey": api_key, "Accept": "application/json", "x-tool": "TraceCat"}


def _encode_url_id(url: str) -> str:
    """Encode a URL to its GTI URL identifier (base64url without padding).

    GTI expects URLs to be base64url-encoded with padding stripped.
    See: https://docs.virustotal.com/reference/url-info
    """
    url_bytes = url.encode("utf-8")
    b64 = base64.urlsafe_b64encode(url_bytes).decode("utf-8")
    return b64.rstrip("=")


# =============================================================================
# Core Lookups
# =============================================================================


@registry.register(
    default_title="Lookup domain",
    display_group="GTI",
    description="Get GTI report for a domain.",
    namespace="tools.gti",
    doc_url="https://docs.virustotal.com/reference/domain-info",
    secrets=[gti_secret],
)
async def lookup_domain(
    domain: Annotated[
        str,
        Field(description="Domain to lookup (e.g., 'example.com')"),
    ],
) -> dict[str, Any]:
    """
    Get the GTI report for a domain.

    Returns comprehensive domain analysis including:
    - Last analysis stats (malicious, suspicious, harmless, undetected counts)
    - DNS records, WHOIS data, registrar info
    - Reputation score
    - Categories assigned by security vendors
    - Historical analysis results

    Example domains: 'malware.com', 'google.com'
    """
    headers = _get_headers()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{GTI_BASE_URL}/domains/{domain}",
            headers=headers,
        )
        response.raise_for_status()
        return response.json()


@registry.register(
    default_title="Lookup file hash",
    display_group="GTI",
    description="Get GTI report for a file hash.",
    namespace="tools.gti",
    doc_url="https://docs.virustotal.com/reference/file-info",
    secrets=[gti_secret],
)
async def lookup_file_hash(
    file_hash: Annotated[
        str,
        Field(description="File hash to lookup (MD5, SHA-1, or SHA-256)"),
    ],
) -> dict[str, Any]:
    """
    Get the GTI report for a file hash.

    Accepts MD5, SHA-1, or SHA-256 hashes.

    Returns comprehensive file analysis including:
    - Last analysis stats (malicious, suspicious, harmless, undetected counts)
    - Detection results from all scanning engines
    - File metadata (size, type, names, tags)
    - Signature information
    - Behavioral analysis summary
    """
    headers = _get_headers()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{GTI_BASE_URL}/files/{file_hash}",
            headers=headers,
        )
        response.raise_for_status()
        return response.json()


@registry.register(
    default_title="Lookup IP address",
    display_group="GTI",
    description="Get GTI report for an IP address.",
    namespace="tools.gti",
    doc_url="https://docs.virustotal.com/reference/ip-info",
    secrets=[gti_secret],
)
async def lookup_ip_address(
    ip_address: Annotated[
        str,
        Field(description="IP address to lookup (e.g., '8.8.8.8')"),
    ],
) -> dict[str, Any]:
    """
    Get the GTI report for an IP address.

    Returns comprehensive IP analysis including:
    - Last analysis stats (malicious, suspicious, harmless, undetected counts)
    - ASN, country, network owner information
    - Reputation score
    - WHOIS data
    - Historical analysis results
    """
    headers = _get_headers()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{GTI_BASE_URL}/ip_addresses/{ip_address}",
            headers=headers,
        )
        response.raise_for_status()
        return response.json()


@registry.register(
    default_title="Lookup URL",
    display_group="GTI",
    description="Get GTI report for a URL.",
    namespace="tools.gti",
    doc_url="https://docs.virustotal.com/reference/url-info",
    secrets=[gti_secret],
)
async def lookup_url(
    url: Annotated[
        str,
        Field(description="URL to lookup (e.g., 'https://example.com/path')"),
    ],
) -> dict[str, Any]:
    """
    Get the GTI report for a URL.

    The URL is automatically base64url-encoded as required by the API.

    Returns comprehensive URL analysis including:
    - Last analysis stats (malicious, suspicious, harmless, undetected counts)
    - Final URL (after redirects)
    - HTTP response details
    - Categories assigned by security vendors
    - Outgoing links, redirects, trackers
    """
    headers = _get_headers()
    url_id = _encode_url_id(url)

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{GTI_BASE_URL}/urls/{url_id}",
            headers=headers,
        )
        response.raise_for_status()
        return response.json()
