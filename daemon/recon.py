"""AegisSIEM Daemon - Passive reconnaissance: WHOIS, rDNS, GeoIP."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from typing import Optional

import httpx

from .db import Database
from .models import AttackerProfile

logger = logging.getLogger(__name__)

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_private(ip: str) -> bool:
    """Check if an IP is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return True


async def whois_lookup(ip: str) -> dict:
    """Run WHOIS lookup via subprocess and parse key fields.

    Returns dict with: org, netblock, country, abuse_contact
    """
    result: dict[str, Optional[str]] = {
        "org": None,
        "netblock": None,
        "country": None,
        "abuse_contact": None,
    }

    if is_private(ip):
        return result

    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        text = stdout.decode(errors="replace")

        # Parse organization
        org_match = re.search(r"(?:OrgName|org-name|Organization):\s*(.+)", text, re.IGNORECASE)
        if org_match:
            result["org"] = org_match.group(1).strip()

        # Parse netblock / CIDR
        net_match = re.search(r"(?:CIDR|inetnum|NetRange):\s*(.+)", text, re.IGNORECASE)
        if net_match:
            result["netblock"] = net_match.group(1).strip()

        # Parse country
        country_match = re.search(r"(?:Country):\s*(\S+)", text, re.IGNORECASE)
        if country_match:
            result["country"] = country_match.group(1).strip().upper()

        # Parse abuse contact
        abuse_match = re.search(r"(?:OrgAbuseEmail|abuse-mailbox):\s*(\S+)", text, re.IGNORECASE)
        if abuse_match:
            result["abuse_contact"] = abuse_match.group(1).strip()

    except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
        logger.warning("WHOIS lookup failed for %s: %s", ip, e)

    return result


async def reverse_dns(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup via dig."""
    if is_private(ip):
        return None

    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "-x", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        hostname = stdout.decode(errors="replace").strip()
        return hostname if hostname and hostname != ip else None
    except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
        logger.warning("rDNS lookup failed for %s: %s", ip, e)
        return None


async def geoip_lookup(ip: str) -> dict:
    """GeoIP lookup via ip-api.com (free tier, no key needed).

    Returns dict with: country, city, asn, asn_org
    """
    result: dict[str, Optional[str]] = {
        "country": None,
        "city": None,
        "asn": None,
        "asn_org": None,
    }

    if is_private(ip):
        return result

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,as,org,isp")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    result["country"] = data.get("country")
                    result["city"] = data.get("city")
                    result["asn"] = data.get("as")
                    result["asn_org"] = data.get("org") or data.get("isp")
    except (httpx.HTTPError, Exception) as e:
        logger.warning("GeoIP lookup failed for %s: %s", ip, e)

    return result


async def run_recon(db: Database, ip: str) -> Optional[AttackerProfile]:
    """Run all reconnaissance in parallel and update the profile in the database.

    Args:
        db: Database instance.
        ip: Target IP address.

    Returns:
        Updated AttackerProfile or None if IP is private.
    """
    if is_private(ip):
        logger.debug("Skipping recon for private IP %s", ip)
        return None

    logger.info("Running recon for %s", ip)

    # Run all lookups in parallel
    whois_result, rdns_result, geoip_result = await asyncio.gather(
        whois_lookup(ip),
        reverse_dns(ip),
        geoip_lookup(ip),
        return_exceptions=True,
    )

    # Handle exceptions from gather
    if isinstance(whois_result, Exception):
        logger.warning("WHOIS failed for %s: %s", ip, whois_result)
        whois_result = {}
    if isinstance(rdns_result, Exception):
        logger.warning("rDNS failed for %s: %s", ip, rdns_result)
        rdns_result = None
    if isinstance(geoip_result, Exception):
        logger.warning("GeoIP failed for %s: %s", ip, geoip_result)
        geoip_result = {}

    profile = db.get_profile_by_ip(ip)
    if not profile:
        # Compute /24 subnet
        parts = ip.rsplit(".", 1)
        subnet_24 = f"{parts[0]}.0/24" if len(parts) == 2 else None
        from datetime import datetime

        profile = AttackerProfile(
            ip=ip,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            subnet_24=subnet_24,
        )

    # Merge WHOIS data
    if whois_result.get("org"):
        profile.whois_org = whois_result["org"]
    if whois_result.get("netblock"):
        profile.whois_netblock = whois_result["netblock"]
    if whois_result.get("country") and not profile.country:
        profile.country = whois_result["country"]

    # Merge rDNS
    if rdns_result:
        profile.reverse_dns = rdns_result

    # Merge GeoIP
    if geoip_result.get("country"):
        profile.country = geoip_result["country"]
    if geoip_result.get("city"):
        profile.city = geoip_result["city"]
    if geoip_result.get("asn"):
        profile.asn = geoip_result["asn"]
    if geoip_result.get("asn_org"):
        profile.asn_org = geoip_result["asn_org"]

    db.upsert_profile(profile)
    logger.info("Recon complete for %s: country=%s org=%s", ip, profile.country, profile.whois_org)
    return profile
