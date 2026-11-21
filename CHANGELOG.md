# Changelog

## Unreleased

### Fixed

- A forged `Authentication-Results` header below a receiving-server header with no results
  (`mx.example; none`) was trusted. The topmost header is now chosen before empty ones are
  dropped, and lower headers claiming a pass the receiving server did not verify are flagged.
- A lower header copying the receiving server's `authserv-id` was trusted as the same server.
- `Received-SPF` from the receiving server now beats `Authentication-Results` written below it.
- New `DAYAG_TRUSTED_AUTHSERV` setting: trust only the named receiving servers' headers.
- Malformed headers no longer crash the analysis: bad charsets and encoded words, attached
  messages that cannot be re-serialised, a NUL in a body charset, and raw 8-bit bytes reaching
  the STIX export. Raw UTF-8 headers are now decoded instead of shown as escapes.

## 0.1.0 - 2026-11-02

First release.

- 70 detection rules across authentication, sender, links, attachments, content and
  infrastructure, each mapped to MITRE ATT&CK where one applies.
- Lookalike-domain detection: homoglyphs, character swaps, typos, TLD swaps and brand names.
- Unwrapping of Microsoft Safe Links, Proofpoint URL Defense, Google and Barracuda redirects.
- Static attachment analysis: magic bytes, archives, OOXML/OLE macros, remote templates, PDF
  active content, HTML smuggling.
- English and Hebrew phrase detection.
- Reported-phish unwrapping (emails forwarded as attachments).
- Optional online lookups: RDAP domain age, DNS, VirusTotal, AbuseIPDB.
- IOC export as CSV, JSON and STIX 2.1.
- Terminal, JSON and standalone HTML reports; FastAPI web UI and JSON API; Docker image.
- Seven synthetic samples and 177 tests.
