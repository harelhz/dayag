"""Web UI and JSON API (FastAPI).

Stateless by design: uploads are analysed in memory and discarded, and
downloads are embedded in the result page as data: URLs, so nothing about an
email is ever written to disk or kept between requests.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Awaitable, Callable
from importlib.resources import files
from typing import Annotated, Any

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..analyzer import analyze
from ..config import Config
from ..demo import SAMPLES, get_sample
from ..iocs import iocs_to_csv, iocs_to_stix
from ..model import Report
from ..parsing import MAX_EMAIL_BYTES, EmailTooLarge
from ..render.html import environment, render_html

# Multipart overhead on top of the largest email we accept.
MAX_REQUEST_BYTES = MAX_EMAIL_BYTES + 1024 * 1024

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
}


def _data_url(content: str, mime: str) -> str:
    return f"data:{mime};base64,{base64.b64encode(content.encode()).decode()}"


def _downloads(report: Report) -> list[dict[str, str]]:
    stamp = report.analyzed_at.strftime("%Y%m%d-%H%M%S")
    return [
        {
            "label": "HTML report",
            "filename": f"dayag-{stamp}.html",
            "href": _data_url(render_html(report), "text/html"),
        },
        {
            "label": "JSON",
            "filename": f"dayag-{stamp}.json",
            "href": _data_url(
                json.dumps(report.to_dict(), indent=2, ensure_ascii=False), "application/json"
            ),
        },
        {
            "label": "IOCs (CSV)",
            "filename": f"dayag-{stamp}-iocs.csv",
            "href": _data_url(iocs_to_csv(report), "text/csv"),
        },
        {
            "label": "STIX 2.1",
            "filename": f"dayag-{stamp}-stix.json",
            "href": _data_url(iocs_to_stix(report), "application/json"),
        },
    ]


def create_app(config: Config | None = None) -> FastAPI:
    settings = config or Config.from_env()
    app = FastAPI(
        title="Dayag", version=__version__, docs_url=None, redoc_url=None, openapi_url=None
    )
    app.mount(
        "/static", StaticFiles(directory=str(files("dayag").joinpath("static"))), name="static"
    )
    env = environment()

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        length = request.headers.get("content-length", "")
        if length.isdigit() and int(length) > MAX_REQUEST_BYTES:
            response: Response = PlainTextResponse("Email too large.", status_code=413)
        else:
            response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    def page(template: str, status: int = 200, **context: Any) -> HTMLResponse:
        html = env.get_template(template).render(**context)
        return HTMLResponse(html, status_code=status)

    def index_page(error: str = "", status: int = 200) -> HTMLResponse:
        return page(
            "web_index.html.j2",
            status,
            samples=SAMPLES,
            error=error,
            max_mb=MAX_EMAIL_BYTES // (1024 * 1024),
        )

    def result_page(raw: bytes, online: bool) -> HTMLResponse:
        try:
            report = analyze(raw, online=online, config=settings)
        except EmailTooLarge as error:
            return index_page(str(error).capitalize() + ".", 413)
        return page("web_result.html.j2", r=report, downloads=_downloads(report))

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return index_page()

    @app.post("/analyze", response_class=HTMLResponse)
    def analyze_upload(
        file: Annotated[UploadFile | None, File()] = None,
        raw: Annotated[str, Form()] = "",
        online: Annotated[bool, Form()] = False,
    ) -> HTMLResponse:
        data = file.file.read(MAX_EMAIL_BYTES + 1) if file is not None and file.filename else b""
        if not data and raw.strip():
            data = raw.encode("utf-8", errors="replace")
        if not data.strip():
            return index_page("Choose an .eml file or paste the message source.", 400)
        return result_page(data, online)

    @app.post("/analyze/sample", response_class=HTMLResponse)
    def analyze_sample(name: Annotated[str, Form()]) -> HTMLResponse:
        sample = get_sample(name)
        if sample is None:
            return index_page("Unknown sample.", 404)
        return result_page(sample.read(), online=False)

    @app.post("/api/analyze")
    async def api_analyze(request: Request, online: bool = False) -> JSONResponse:
        """POST the raw email as the request body; returns the report as JSON."""
        body = await request.body()
        if not body.strip():
            return JSONResponse({"error": "empty request body"}, status_code=400)
        try:
            report = await run_in_threadpool(analyze, body, online=online, config=settings)
        except EmailTooLarge as error:
            return JSONResponse({"error": str(error)}, status_code=413)
        return JSONResponse(report.to_dict())

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app
