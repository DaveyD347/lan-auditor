"""MAC address vendor (OUI) lookup.

Ships with a small built-in table of vendors common on home networks and can
download the full IEEE MA-L registry into a local cache with
``lan-auditor update-oui``. Wireshark ``manuf`` files and IEEE ``oui.txt`` /
``oui.csv`` files are also accepted via ``--oui-file``.
"""

from __future__ import annotations

import csv
import io
import os
import re
import urllib.request
from importlib import resources
from pathlib import Path

IEEE_OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
_HEX = re.compile(r"[^0-9A-Fa-f]")


def normalize_mac(mac: str) -> str | None:
    """Return ``AA:BB:CC:DD:EE:FF`` or ``None`` if ``mac`` is not a MAC address."""
    digits = _HEX.sub("", mac or "")
    if len(digits) != 12:
        return None
    digits = digits.upper()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def is_locally_administered(mac: str) -> bool:
    """True for randomised/private MACs (the 0x02 bit of the first octet).

    Modern phones and laptops use these for privacy, so they will never match
    a vendor in the registry.
    """
    norm = normalize_mac(mac)
    return bool(norm) and bool(int(norm[:2], 16) & 0x02)


def default_cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(Path.home(), ".cache")
    return Path(base) / "lan-auditor" / "oui.csv"


def parse_oui_text(text: str) -> dict[str, str]:
    """Parse any supported OUI file format into ``{"AABBCC": "Vendor"}``.

    Supported formats:
    * simple ``AABBCC,Vendor`` lines (the built-in table and our cache)
    * IEEE ``oui.csv`` (``Registry,Assignment,Organization Name,...``)
    * IEEE ``oui.txt`` (``AA-BB-CC   (hex)\\t\\tVendor``)
    * Wireshark ``manuf`` (``AA:BB:CC\\tShort\\tLong name``)
    """
    table: dict[str, str] = {}
    first = text.lstrip().split("\n", 1)[0]
    if first.startswith("Registry,Assignment"):
        for row in csv.DictReader(io.StringIO(text)):
            assignment = (row.get("Assignment") or "").strip().upper()
            name = (row.get("Organization Name") or "").strip()
            if len(assignment) == 6 and name:
                table[assignment] = name
        return table

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "(hex)" in line:
            prefix, _, name = line.partition("(hex)")
            key = _HEX.sub("", prefix).upper()
            if len(key) == 6 and name.strip():
                table[key] = name.strip()
            continue
        if "\t" in line:
            fields = [f.strip() for f in line.split("\t") if f.strip()]
            prefix = fields[0]
            # Skip manuf entries for longer (MA-M/MA-S) prefixes, e.g. "/28".
            if "/" in prefix:
                continue
            key = _HEX.sub("", prefix).upper()
            if len(key) == 6 and len(fields) > 1:
                table[key] = fields[-1]
            continue
        if "," in line:
            prefix, _, name = line.partition(",")
            key = _HEX.sub("", prefix).upper()
            name = name.strip().strip('"').replace('""', '"')
            if len(key) == 6 and name:
                table[key] = name
    return table


class OUILookup:
    """Maps MAC addresses to vendor names."""

    def __init__(self, table: dict[str, str] | None = None) -> None:
        self.table = table if table is not None else {}

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> OUILookup:
        """Load the built-in table, overlaid with the cache or ``path`` if present."""
        builtin = resources.files("lanaudit").joinpath("data/oui_builtin.csv").read_text("utf-8")
        table = parse_oui_text(builtin)
        candidate = Path(path) if path else default_cache_path()
        if candidate.is_file():
            table.update(parse_oui_text(candidate.read_text("utf-8", errors="replace")))
        return cls(table)

    def lookup(self, mac: str | None) -> str | None:
        if not mac:
            return None
        norm = normalize_mac(mac)
        if not norm:
            return None
        vendor = self.table.get(norm.replace(":", "")[:6])
        if vendor:
            return vendor
        if is_locally_administered(norm):
            return "(randomised / locally administered MAC)"
        return None

    def __len__(self) -> int:
        return len(self.table)


def update_cache(
    dest: Path | None = None, url: str = IEEE_OUI_CSV_URL, timeout: float = 60
) -> tuple[Path, int]:
    """Download the IEEE registry and save it as a compact ``AABBCC,Vendor`` file."""
    dest = dest or default_cache_path()
    req = urllib.request.Request(url, headers={"User-Agent": "lan-auditor"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
        text = resp.read().decode("utf-8", errors="replace")
    table = parse_oui_text(text)
    if not table:
        raise RuntimeError("downloaded OUI file contained no entries")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        for key in sorted(table):
            writer.writerow([key, table[key]])
    return dest, len(table)
