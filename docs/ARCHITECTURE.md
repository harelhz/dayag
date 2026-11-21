# Architecture and design decisions

## Pipeline

```
raw bytes
  │  parsing.py      load_message(), find_reported_message(), extract()
  ▼
ParsedEmail          headers (raw), text bodies, HTML bodies, attachments (bytes)
  │  context.py      build_context()
  ▼
Context              sender, Reply-To, auth summary, hops, links (unwrapped),
  │                  attachments (sniffed, hashed, listed), HTML scan, normalised text
  │  checks/*.py     check_authentication, check_sender, check_links,
  ▼                  check_attachments, check_content, check_infrastructure
list[Finding]        each finding = rule from rules.py + detail + evidence
  │  enrich/*.py     only with --online: DNS, RDAP, VirusTotal, AbuseIPDB
  │  scoring.py      merge_findings(), score(), verdict_for()
  │  iocs.py         collect_iocs()
  ▼
Report               rendered by render/terminal.py, render/html.py, or as JSON
```

**Facts and judgements are separate.** `context.py`, `headers.py`, `filetypes.py` and `urls.py`
only extract: they never decide whether something is bad. The checks only judge. A new check
can therefore reuse every extracted fact, and extraction can be tested without any opinions
involved.

**Rules are data.** Every finding refers to a rule in `rules.py` by ID. The rule carries the
title, severity, points, rationale and ATT&CK techniques. The checks contain no scores, and
`docs/DETECTIONS.md` is generated from the same table (a test fails if it is stale).

## Decisions worth explaining

### Which authentication headers to trust

Any sender can add an `Authentication-Results: ...; dmarc=pass` header before sending. RFC 8601
headers are added by the *receiving* server at the top of the message, so Dayag trusts the
topmost header, plus any directly below it from the same server (same `authserv-id`). A lower
header that copies the receiving server's `authserv-id` is not trusted. A topmost header with no
results (`mx.example; none`) means the receiving server gave no verdict, not that the next header
down should be believed. Lower headers that claim `pass` where the receiving server said otherwise,
or gave no SPF, DKIM, DMARC or CompAuth verdict at all, become the `AUTH-FORGED-RESULTS` finding.
The DHL sample has one.

When the receiving server wrote a `Received-SPF` header but no `Authentication-Results`, every
`Authentication-Results` header sits below a `Received` hop under the `Received-SPF` one. Dayag
then trusts `Received-SPF` and treats all of them as written by the sender.

Position alone cannot spot a forged header when the receiving server wrote no authentication
headers at all. Set `DAYAG_TRUSTED_AUTHSERV` to your receiving servers' `authserv-id`s
(comma-separated) and only their headers are trusted, wherever they sit. Exchange Online writes
its headers without an `authserv-id`, so leave the setting unset for Microsoft 365 mail.

Dayag does not re-verify DKIM itself. The receiving server checked the signature at delivery
time, when the key was current. A later check can fail only because the key has been rotated.

### DMARC pass is not "safe"

DMARC proves the From domain is authentic. Attackers register `paypal-resolution-center.com` and
set up SPF, DKIM and DMARC for it, so a pass is worth only −10 points. A lookalike domain alone
is worth +30 to +50.

### Lookalike detection

`domains.find_lookalike()` compares the registrable label (from the Public Suffix List, private
section included, so on `evil.web.app` the label is `evil`) with each brand's labels:

1. **Skeleton.** Both strings are mapped to what they look like: Cyrillic and Greek confusables
   become Latin, accents are stripped (NFKD), `0→o`, `1/i/l→l`, `rn→m`, `vv→w`. If the skeletons
   match but the strings don't, it is a homoglyph (non-ASCII) or a character swap (ASCII).
2. **Typo.** Edit distance with transpositions (`pyapal`) ≤ 1, or ≤ 2 for long brand names.
   Typosquats keep the first letter, and a small exception list stops `apply` from matching
   `apple`; without this, `finance.com` would be a typo of `binance.com`.
3. **Combosquat.** Each hyphen-separated part is compared the same way, so `micros0ft-security`
   is still a character swap. A brand name embedded in the label or a subdomain
   (`paypal.com.verify.xyz`) is the weaker "brand name" technique.

Strong techniques (homoglyph, character swap, typo, TLD swap) are critical. Brand-name use is
high, because `paypal-community.com` style domains are sometimes legitimate.

### Unwrapping security gateways

Mail that passes through Microsoft Defender or Proofpoint has its links rewritten. Judging
`eur03.safelinks.protection.outlook.com` would be useless, so `urls.unwrap()` decodes Safe Links
(`url=`), Proofpoint v2 (`u=` with its `-`/`_` encoding) and v3 (`__...__;`), Google redirects
and Barracuda. It does this up to three times, for nested wrappers. The report keeps the original
URL and names the wrapper.

### Scoring

Points add up, but each rule counts once (`merge_findings`). Without this, an email with 30
shortened links would outscore one with a single lookalike link. The thresholds (15/40/70) are
tuned so that:

- a legitimate email with tracking and an ESP sender stays at 0,
- a BEC email with no links or attachments (Reply-To diversion + payment pressure) reaches
  "likely phishing", and
- any single critical finding reaches at least "likely phishing" even after a DMARC pass.

### IOCs that can go straight into a blocklist

Every indicator is listed, but only *flagged* ones go into the STIX bundle. Shared
infrastructure is never flagged as a host: free-mail domains, brand domains, newsletter click
trackers, shorteners and IPFS gateways. The URL `https://bit.ly/abc` is an indicator; `bit.ly`
is not. The relay IP of an Outlook.com BEC email belongs to Microsoft, so it is not flagged
either.

### Robust parsing

Phishing emails are often malformed on purpose. Headers are read with `raw_items()` and decoded
by hand, because the email package's structured header parser can raise on malformed values.
Addresses are parsed *before* decoding RFC 2047 words (a decoded `Levi, Alice` would split into
two addresses), and if a From header still yields several entries the one with an `@` wins.

### Static attachment analysis only

- File type comes from magic bytes, never from the name or declared MIME type.
- Archives are listed from the central directory. Only small `.rels` files inside Office
  documents are read, capped at 1 MB.
- PDF streams are inflated with `zlib.decompressobj().decompress(data, max_length)`, so a PDF
  bomb stops at 5 MB per stream, 200 streams at most.
- The OOXML and OLE checks look for `vbaProject.bin` / `_VBA_PROJECT` instead of parsing VBA,
  which is enough to know macros are present.

## Testing strategy

- **Golden samples**: every bundled sample has an expected verdict and a set of rules that must
  fire (`tests/test_samples.py`). The samples are generated by `scripts/make_samples.py`, and CI
  checks that regenerating them changes nothing.
- **Unit tests per check** craft minimal emails with `tests/conftest.build_email()`.
- **Hostile-input tests**: XSS payloads and terminal escape sequences in every field
  (`tests/test_render.py`), malformed MIME, zip bombs, path traversal against the sample endpoint.
- **Network is always mocked** (`respx`), including a test that the offline mode makes no
  requests at all and one that lookups only send GET requests with the API key in a header.
