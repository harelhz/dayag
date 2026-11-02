# Security

## Reporting a vulnerability

Please open a [private security advisory](https://github.com/harelhz/dayag/security/advisories/new)
instead of a public issue. I aim to reply within a week.

## Threat model

Dayag processes email written by attackers, and its users are analysts who may open the output
in a browser or terminal. The goal is that analyzing an email is never more dangerous than not
analyzing it.

| Threat | Mitigation |
| --- | --- |
| **Script injection into the HTML report** (subject, names or URLs containing `<script>`) | Jinja2 autoescaping everywhere. Email data is never marked safe. Links are rendered as defanged text, not `<a>` elements. The standalone report carries `Content-Security-Policy: default-src 'none'` and the web UI a strict CSP. Covered by `tests/test_render.py`. |
| **Terminal escape injection** (ANSI sequences in a subject) | All email text passes through `text.for_display()`, which strips C0/C1 control characters, and is printed as `rich.Text`, never parsed as markup. |
| **Misleading display** (right-to-left override in file names) | Bidi control characters are shown as visible `[U+202E]` markers, and their presence is a finding. |
| **Tipping off the attacker** (tracking pixels, link visits) | HTML is never rendered, images never loaded, links never followed. Online lookups query reputation services, never the attacker's infrastructure. |
| **Leaking a targeted email** to third parties | Offline by default. With `--online`, only read-only GET lookups of hashes, domains and URL IDs. Nothing is uploaded or submitted. API keys are sent in headers, never in URLs. |
| **Resource exhaustion** (zip bombs, PDF bombs, huge emails) | 25 MB email cap, enforced before parsing and by the web server on Content-Length. Archives are listed, never extracted. All decompression is size-capped. HTML scanning is capped at 2 MB. |
| **Parser crashes on malformed input** | Raw header access, defensive decoding with fallbacks, and tests with deliberately broken MIME. |
| **Path traversal through the web UI** | Samples are looked up by exact name in a fixed list. Uploads are never written to disk. |
| **Exposure of the web UI** | Binds to 127.0.0.1 by default and warns when bound elsewhere. There is no authentication: put it behind your own SSO or VPN before sharing it. |

## Out of scope

- Detonating attachments or visiting links. Use a sandbox for that; Dayag tells you which files
  and URLs deserve one.
- Authentication and multi-user access control for the web UI.
