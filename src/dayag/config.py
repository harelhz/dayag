"""Settings for online lookups, read from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    virustotal_key: str = ""
    abuseipdb_key: str = ""
    timeout: float = 10.0
    max_domain_lookups: int = 8
    max_virustotal_lookups: int = 4  # the free API allows 4 requests per minute

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            virustotal_key=os.environ.get("DAYAG_VIRUSTOTAL_KEY", os.environ.get("VT_API_KEY", "")),
            abuseipdb_key=os.environ.get(
                "DAYAG_ABUSEIPDB_KEY", os.environ.get("ABUSEIPDB_API_KEY", "")
            ),
        )
