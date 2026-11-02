"""Extract what matters from an HTML email body without rendering it."""

from __future__ import annotations

import re
from html.parser import HTMLParser

MAX_HTML_CHARS = 2_000_000

_VOID = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0+(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|!|$)"
    r"|opacity\s*:\s*0+(?:\.0+)?\s*(?:;|!|$)|max-height\s*:\s*0+(?:px)?\s*(?:;|!|$)",
    re.IGNORECASE,
)
_PIXEL_SIZE = re.compile(r"^\s*[01](?:px)?\s*$")
_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.IGNORECASE)


class HtmlScan(HTMLParser):
    """Collects links, forms, images and visible/hidden text from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self.forms: list[str] = []
        self.password_fields = 0
        self.images: list[tuple[str, bool]] = []
        self.scripts = 0
        self.frames: list[str] = []
        self.refresh_urls: list[str] = []
        self.hidden_chars = 0
        self._text: list[str] = []
        self._stack: list[tuple[str, bool]] = []
        self._anchor: tuple[str, list[str]] | None = None
        self._skip = 0

    # Public API ------------------------------------------------------------

    def scan(self, html: str) -> HtmlScan:
        try:
            self.feed(html[:MAX_HTML_CHARS])
            self.close()
        except (AssertionError, ValueError):  # pragma: no cover - parser is lenient
            pass
        return self

    @property
    def text(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self._text)).strip()

    # HTMLParser hooks ------------------------------------------------------

    def _hidden(self) -> bool:
        return bool(self._stack) and self._stack[-1][1]

    def _open(self, tag: str, attrs: list[tuple[str, str | None]], push: bool) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        style = a.get("style", "")
        hidden = self._hidden() or "hidden" in a or bool(_HIDDEN_STYLE.search(style))
        if tag in ("a", "area") and a.get("href"):
            if tag == "a" and push:
                self._finish_anchor()
                self._anchor = (a["href"], [])
            else:
                self.anchors.append((a["href"], a.get("alt", "")))
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.password_fields += 1
        elif tag == "img":
            width, height = a.get("width", ""), a.get("height", "")
            pixel = bool(_PIXEL_SIZE.match(width) and _PIXEL_SIZE.match(height)) or bool(
                re.search(r"width\s*:\s*[01]px", style) and re.search(r"height\s*:\s*[01]px", style)
            )
            self.images.append((a.get("src", ""), pixel))
        elif tag in ("script", "style", "title"):
            if tag == "script":
                self.scripts += 1
            if push:
                self._skip += 1
        elif tag in ("iframe", "frame", "embed", "object"):
            source = a.get("src") or a.get("data", "")
            if source:
                self.frames.append(source)
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            match = _REFRESH_URL.search(a.get("content", ""))
            if match:
                self.refresh_urls.append(match.group(1).strip())
        if push and tag not in _VOID:
            self._stack.append((tag, hidden))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._open(tag, attrs, push=True)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._open(tag, attrs, push=False)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._finish_anchor()
        if tag in ("script", "style", "title") and self._skip:
            self._skip -= 1
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._hidden():
            self.hidden_chars += len(data.strip())
            return
        if self._anchor is not None:
            self._anchor[1].append(data)
        self._text.append(data)

    def close(self) -> None:
        super().close()
        self._finish_anchor()

    def _finish_anchor(self) -> None:
        if self._anchor is not None:
            href, parts = self._anchor
            self.anchors.append((href, re.sub(r"\s+", " ", "".join(parts)).strip()))
            self._anchor = None
