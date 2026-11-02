"""Offline checks. Each takes the shared Context and returns findings."""

from __future__ import annotations

from collections.abc import Callable

from ..context import Context
from ..model import Finding
from .attachments import check_attachments
from .auth import check_authentication
from .content import check_content
from .infrastructure import check_infrastructure
from .links import check_links
from .sender import check_sender

Check = Callable[[Context], list[Finding]]

ALL_CHECKS: tuple[Check, ...] = (
    check_authentication,
    check_sender,
    check_links,
    check_attachments,
    check_content,
    check_infrastructure,
)

__all__ = ["ALL_CHECKS", "Check"]
