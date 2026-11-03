"""
geo.py – GeoIP lookup using MaxMind GeoLite2.

Tries to load GeoLite2-City.mmdb from a few standard locations.
Falls back to a no-op if the database isn't installed.
"""

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("netguard.geo")

_reader = None
_SEARCH_PATHS = [
    Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
    Path("/var/lib/GeoIP/GeoLite2-City.mmdb"),
    Path("/opt/netguard/GeoLite2-City.mmdb"),
    Path("GeoLite2-City.mmdb"),
]


def init(extra_path: str | None = None):
    """Try to open the GeoLite2 database."""
    global _reader
    paths = list(_SEARCH_PATHS)
    if extra_path:
        paths.insert(0, Path(extra_path))

    try:
        import geoip2.database
    except ImportError:
        logger.warning("geoip2 not installed – geo lookups disabled")
        return

    for p in paths:
        if p.is_file():
            try:
                _reader = geoip2.database.Reader(str(p))
                logger.info("Loaded GeoIP database: %s", p)
                return
            except Exception:
                logger.exception("Failed to open %s", p)

    logger.warning(
        "GeoLite2-City.mmdb not found in %s – geo lookups disabled. "
        "Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
        [str(p) for p in paths],
    )


def lookup(ip: str) -> dict[str, Any]:
    """Return country, city, latitude, longitude for an IP."""
    if _reader is None:
        return {"country": "", "city": "", "lat": 0, "lon": 0}
    try:
        resp = _reader.city(ip)
        return {
            "country": resp.country.iso_code or "",
            "city":    resp.city.name or "",
            "lat":     resp.location.latitude or 0,
            "lon":     resp.location.longitude or 0,
        }
    except Exception:
        return {"country": "", "city": "", "lat": 0, "lon": 0}

