"""The bundled sample emails (see scripts/make_samples.py)."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable

SAMPLES_DIR = files("dayag").joinpath("samples")


@dataclass(frozen=True)
class Sample:
    name: str
    title: str

    @property
    def path(self) -> Traversable:
        return SAMPLES_DIR.joinpath(self.name)

    def read(self) -> bytes:
        return self.path.read_bytes()


SAMPLES: tuple[Sample, ...] = (
    Sample("01-github-notification.eml", "GitHub notification (legitimate)"),
    Sample("02-paypal-homoglyph.eml", "PayPal homoglyph link"),
    Sample("03-html-smuggling-invoice.eml", "Invoice with HTML smuggling"),
    Sample("04-ceo-fraud.eml", "CEO fraud (BEC)"),
    Sample("05-israel-post-customs.eml", "Israel Post customs fee (Hebrew)"),
    Sample("06-reported-m365-phish.eml", "User-reported Microsoft 365 phish"),
    Sample("07-dhl-shipping-documents.eml", "DHL remote template and PDF"),
)


def get_sample(name: str) -> Sample | None:
    """Look a sample up by exact name, so user input never becomes a path."""
    return next((s for s in SAMPLES if s.name == name), None)
