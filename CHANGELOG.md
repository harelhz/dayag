# Changelog

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
