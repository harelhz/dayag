"""Settings for online lookups, read from the environment."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    virustotal_key: str = ""
    abuseipdb_key: str = ""
    timeout: float = 10.0
    max_domain_lookups: int = 8
    max_virustotal_lookups: int = 4  # the free API allows 4 requests per minute
    # authserv-ids of your own receiving servers, e.g. ("mx.contoso.com",). When set,
    # only Authentication-Results headers from these servers are trusted. Exchange Online
    # writes no authserv-id, so its headers never match.
    trusted_authserv: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            virustotal_key=os.environ.get("DAYAG_VIRUSTOTAL_KEY", os.environ.get("VT_API_KEY", "")),
            abuseipdb_key=os.environ.get(
                "DAYAG_ABUSEIPDB_KEY", os.environ.get("ABUSEIPDB_API_KEY", "")
            ),
            trusted_authserv=tuple(
                part.lower()
                for part in re.split(r"[\s,]+", os.environ.get("DAYAG_TRUSTED_AUTHSERV", ""))
                if part
            ),
        )
