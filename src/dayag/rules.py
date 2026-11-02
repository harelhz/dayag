"""Every detection Dayag can raise, in one table.

Checks refer to rules by ID, so a rule's title, severity, score and MITRE
ATT&CK mapping live here and nowhere else. docs/DETECTIONS.md is generated
from this table (`dayag rules --markdown`) and a test keeps the two in sync.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


class Category(StrEnum):
    AUTHENTICATION = "authentication"
    SENDER = "sender"
    LINKS = "links"
    ATTACHMENTS = "attachments"
    CONTENT = "content"
    INFRASTRUCTURE = "infrastructure"
    META = "meta"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: Category
    severity: Severity
    points: int
    rationale: str
    attack: tuple[str, ...] = ()
    online: bool = False


_A, _S, _L, _F, _C, _I, _M = (
    Category.AUTHENTICATION,
    Category.SENDER,
    Category.LINKS,
    Category.ATTACHMENTS,
    Category.CONTENT,
    Category.INFRASTRUCTURE,
    Category.META,
)
_INFO, _LOW, _MED, _HIGH, _CRIT = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)

# fmt: off
_RULES: tuple[Rule, ...] = (
    # Authentication ------------------------------------------------------
    Rule("AUTH-DMARC-FAIL", "DMARC failed", _A, _HIGH, 30,
         "Neither SPF nor DKIM passed in alignment with the From domain. This is what a forged "
         "From address looks like.", ("T1566",)),
    Rule("AUTH-COMPAUTH-FAIL", "Microsoft composite authentication failed", _A, _HIGH, 30,
         "Exchange Online combined SPF, DKIM, DMARC and its own reputation data and concluded "
         "that the sender is not who it claims to be.", ("T1566",)),
    Rule("AUTH-FORGED-RESULTS", "Forged authentication header", _A, _MED, 15,
         "An Authentication-Results header lower in the message claims a pass that the receiving "
         "server did not report. Senders can add any header they like, so only the topmost "
         "results, written by the receiving server, are trusted.", ("T1566",)),
    Rule("AUTH-SPF-FAIL", "SPF failed", _A, _MED, 15,
         "The server that delivered the email is not allowed to send for the envelope sender's "
         "domain. Alone it can be a misconfigured forwarder; with a DMARC failure it means the "
         "sender is forged.", ("T1566",)),
    Rule("AUTH-SPF-SOFTFAIL", "SPF soft-failed", _A, _LOW, 5,
         "The envelope sender's domain says this server is probably not one of its own."),
    Rule("AUTH-SPF-NONE", "No usable SPF result", _A, _LOW, 5,
         "The envelope sender's domain publishes no SPF record, or it could not be evaluated."),
    Rule("AUTH-DKIM-FAIL", "DKIM signature failed", _A, _LOW, 5,
         "The message carries a signature that does not verify: it was changed in transit or the "
         "signature is fake."),
    Rule("AUTH-DKIM-NONE", "Not DKIM-signed", _A, _LOW, 5,
         "Legitimate bulk and corporate senders almost always sign their mail."),
    Rule("AUTH-DMARC-NONE", "From domain has no DMARC policy", _A, _LOW, 5,
         "Without a DMARC policy, receivers have no instruction to reject mail that forges the "
         "domain."),
    Rule("AUTH-DKIM-UNALIGNED", "Signed by a different domain", _A, _INFO, 0,
         "The DKIM signature belongs to another domain, usually an email service provider. Common "
         "and legitimate, but worth knowing when the From domain matters."),
    Rule("AUTH-DMARC-PASS", "DMARC passed", _A, _INFO, -10,
         "The email really comes from the From domain. That proves where it came from, not that "
         "the domain is trustworthy: attackers authenticate their own lookalike domains too."),
    Rule("AUTH-MISSING", "No authentication results", _A, _INFO, 0,
         "The receiving server's verdicts are missing, so SPF, DKIM and DMARC cannot be judged. "
         "Export the original message with full headers if possible."),
    # Sender -------------------------------------------------------------
    Rule("SENDER-LOOKALIKE", "Sender domain imitates a brand", _S, _CRIT, 50,
         "The From or Reply-To domain is a homoglyph, character swap, typo or TLD swap of a "
         "well-known brand's domain.", ("T1583.001", "T1656")),
    Rule("SENDER-COMBOSQUAT", "Sender domain contains a brand name", _S, _HIGH, 30,
         "A brand name combined with other words (paypal-support.com) is the most common way to "
         "register a convincing phishing domain.", ("T1583.001", "T1656")),
    Rule("SENDER-DISPLAY-BRAND", "Display name impersonates a brand", _S, _HIGH, 30,
         "The display name claims to be a brand, but the address does not belong to it. Most mail "
         "apps show only the display name.", ("T1656",)),
    Rule("SENDER-DISPLAY-ADDRESS", "Display name contains a different address", _S, _HIGH, 30,
         'A display name such as "security@bank.com" hides the real sender address in clients '
         "that only show names.", ("T1656",)),
    Rule("SENDER-REPLYTO-FREEMAIL", "Replies go to a free email account", _S, _HIGH, 25,
         "Answers are diverted to a webmail account the attacker controls: the signature move of "
         "business email compromise.", ("T1585.002", "T1656")),
    Rule("SENDER-REPLYTO-MISMATCH", "Replies go to a different domain", _S, _MED, 15,
         "The Reply-To domain differs from the From domain, so a reply would reach someone other "
         "than the apparent sender."),
    Rule("SENDER-FREEMAIL", "Sent from a free email account", _S, _LOW, 5,
         "Anyone can create a free webmail account under any name.", ("T1585.002",)),
    Rule("SENDER-RETURNPATH-MISMATCH", "Envelope sender differs from From", _S, _INFO, 0,
         "Bounces go to another domain. Normal for email service providers, so it only adds "
         "context."),
    Rule("SENDER-NEW-DOMAIN", "Sender domain was registered recently", _S, _HIGH, 30,
         "Phishing domains are typically used within days of registration.", ("T1583.001",),
         online=True),
    Rule("SENDER-NO-MX", "Sender domain cannot receive email", _S, _MED, 15,
         "The domain has no mail server, a sign of a throwaway domain set up only to send.",
         online=True),
    Rule("SENDER-NO-DMARC", "Sender domain publishes no DMARC record", _S, _INFO, 0,
         "Live DNS shows no DMARC record, so the domain can be spoofed freely.", online=True),
    # Links --------------------------------------------------------------
    Rule("LINK-LOOKALIKE", "Link to a lookalike domain", _L, _CRIT, 50,
         "A link points to a homoglyph, character swap, typo or TLD swap of a well-known brand's "
         "domain.", ("T1566.002", "T1583.001")),
    Rule("LINK-COMBOSQUAT", "Link domain contains a brand name", _L, _HIGH, 30,
         "The link's domain uses a brand name it does not belong to.", ("T1566.002", "T1583.001")),
    Rule("LINK-TEXT-MISMATCH", "Link text hides the real destination", _L, _HIGH, 30,
         "The visible link text shows one domain while the link goes to another.",
         ("T1566.002",)),
    Rule("LINK-IP", "Link to a bare IP address", _L, _HIGH, 30,
         "Legitimate services use domain names. Raw IPs are typical of compromised or throwaway "
         "servers.", ("T1566.002",)),
    Rule("LINK-USERINFO", "Link uses the @ trick", _L, _HIGH, 30,
         "In https://bank.com@evil.example/ everything before the @ is a user name and is "
         "ignored: the browser goes to evil.example.", ("T1566.002",)),
    Rule("LINK-SCRIPT-SCHEME", "javascript: or data: link", _L, _HIGH, 30,
         "These links run code or open a page embedded in the link itself, bypassing URL "
         "filtering.", ("T1566.002",)),
    Rule("LINK-IPFS", "Link to an IPFS gateway", _L, _HIGH, 30,
         "Phishing kits are hosted on IPFS because content there is hard to take down.",
         ("T1566.002", "T1583.006")),
    Rule("LINK-PUNYCODE", "Internationalised (punycode) domain", _L, _MED, 15,
         "Non-Latin characters can make a domain look identical to another one.",
         ("T1566.002",)),
    Rule("LINK-SHORTENER", "Shortened link hides the destination", _L, _MED, 15,
         "The real destination is only revealed after clicking.", ("T1566.002",)),
    Rule("LINK-FREE-HOSTING", "Link to a free hosting service", _L, _MED, 15,
         "Free hosting and file-sharing platforms let attackers put a phishing page on a "
         "reputable domain within minutes.", ("T1583.006",)),
    Rule("LINK-CREDENTIAL-PATH", "Login-themed link to an unrelated site", _L, _LOW, 5,
         "The link's path talks about logging in or verifying an account, on a domain that is "
         "neither the sender's nor a known brand's.", ("T1566.002",)),
    Rule("LINK-RISKY-TLD", "Link to a frequently abused TLD", _L, _LOW, 5,
         "Some cheap top-level domains host a disproportionate share of phishing."),
    Rule("LINK-NONSTANDARD-PORT", "Link uses an unusual port", _L, _LOW, 5,
         "Web servers on unusual ports are rare for legitimate services."),
    Rule("LINK-NEW-DOMAIN", "Link domain was registered recently", _L, _HIGH, 25,
         "Phishing pages are typically hosted on domains only days old.", ("T1583.001",),
         online=True),
    Rule("LINK-REPUTATION", "URL or domain flagged by VirusTotal", _L, _CRIT, 50,
         "Several security vendors already classify a URL or domain in this email as malicious.",
         ("T1566.002",), online=True),
    # Attachments --------------------------------------------------------
    Rule("ATT-EXECUTABLE", "Executable or script attachment", _F, _CRIT, 50,
         "The attachment runs code when opened.", ("T1566.001", "T1204.002")),
    Rule("ATT-DOUBLE-EXT", "Double file extension", _F, _CRIT, 50,
         "invoice.pdf.exe looks like a PDF when Windows hides known extensions.",
         ("T1036.007",)),
    Rule("ATT-RTLO", "Right-to-left override in file name", _F, _CRIT, 50,
         "An invisible Unicode control character reverses the end of the name, so "
         "'invoice[U+202E]fdp.exe' is displayed as 'invoiceexe.pdf'.", ("T1036.002",)),
    Rule("ATT-HTML-SMUGGLING", "HTML smuggling", _F, _CRIT, 50,
         "The HTML file builds a file inside the browser from embedded data and offers it as a "
         "download, so the payload never crosses the mail gateway as a file.", ("T1027.006",)),
    Rule("ATT-ARCHIVE-RISKY", "Archive contains executable content", _F, _CRIT, 50,
         "The archive holds executables, scripts, shortcuts or disguised file names.",
         ("T1566.001", "T1204.002")),
    Rule("ATT-TYPE-MISMATCH", "File content does not match its extension", _F, _HIGH, 30,
         "The file's real format, read from its first bytes, differs from what its name claims.",
         ("T1036.008",)),
    Rule("ATT-HTML", "HTML or SVG attachment", _F, _HIGH, 30,
         "Local HTML files are used for credential-harvesting pages that load without any URL "
         "for filters to block.", ("T1566.001",)),
    Rule("ATT-ENCRYPTED-ARCHIVE", "Password-protected archive", _F, _HIGH, 30,
         "Encryption stops the mail gateway from scanning the contents; the password is usually "
         "in the email body.", ("T1027.013",)),
    Rule("ATT-DISK-IMAGE", "Disk image attachment", _F, _HIGH, 30,
         "Files inside ISO, IMG and VHD images do not inherit the Mark of the Web, so Windows "
         "skips its warnings.", ("T1553.005",)),
    Rule("ATT-MACRO", "Office document with macros", _F, _HIGH, 30,
         "VBA macros are a classic first stage for malware.", ("T1566.001", "T1059.005")),
    Rule("ATT-REMOTE-TEMPLATE", "Document loads remote content", _F, _HIGH, 30,
         "The document fetches a template or object from the internet when opened, a way to "
         "deliver macros or exploits after the file has passed scanning.", ("T1221",)),
    Rule("ATT-ONENOTE", "OneNote attachment", _F, _HIGH, 30,
         "OneNote files can embed scripts behind fake 'click to view' buttons.",
         ("T1566.001", "T1204.002")),
    Rule("ATT-PDF-ACTIVE", "PDF with active content", _F, _HIGH, 30,
         "The PDF contains JavaScript, launch actions, embedded files or rich media.",
         ("T1566.001", "T1204.002")),
    Rule("ATT-REPUTATION", "Attachment flagged by VirusTotal", _F, _CRIT, 50,
         "Several security vendors already detect this exact file as malicious.",
         ("T1566.001",), online=True),
    # Content ------------------------------------------------------------
    Rule("CONTENT-PASSWORD-FIELD", "Email asks for a password directly", _C, _CRIT, 50,
         "The email body contains a password field. No legitimate service collects passwords "
         "inside an email.", ("T1566", "T1056.003")),
    Rule("CONTENT-FORM", "Email contains a form", _C, _HIGH, 30,
         "Forms inside an email send whatever the reader types straight to the attacker.",
         ("T1566",)),
    Rule("CONTENT-GIFT-CARD", "Gift card request", _C, _HIGH, 30,
         "Requests to buy gift cards are a hallmark of CEO fraud: they are untraceable and "
         "instantly cashable.", ("T1657",)),
    Rule("CONTENT-SCRIPT", "Email body contains scripts", _C, _MED, 15,
         "Mail clients do not run scripts, so legitimate senders do not include them.",
         ("T1566",)),
    Rule("CONTENT-PAYMENT", "Payment or bank-detail request", _C, _MED, 15,
         "Asks to pay, transfer money or change bank details: the goal of business email "
         "compromise and fake-invoice fraud.", ("T1657",)),
    Rule("CONTENT-CREDENTIALS", "Asks to sign in or verify an account", _C, _MED, 15,
         "Credential phishing almost always asks the reader to log in, verify or update account "
         "details.", ("T1566",)),
    Rule("CONTENT-FAKE-REPLY", "Fake reply or forward", _C, _MED, 15,
         "The subject starts with RE: or FW: but the message is not part of any thread. Pretending "
         "to continue a conversation lowers the reader's guard.", ("T1566",)),
    Rule("CONTENT-URGENCY", "Pressure and urgency", _C, _MED, 10,
         "Deadlines and threats push the reader to act before thinking."),
    Rule("CONTENT-GENERIC-GREETING", "Generic greeting", _C, _LOW, 5,
         "Services you have an account with usually know your name."),
    Rule("CONTENT-HIDDEN-TEXT", "Hidden text", _C, _LOW, 5,
         "Large blocks of invisible text are used to confuse spam filters.", ("T1027",)),
    Rule("CONTENT-IMAGE-ONLY", "Mostly images, little text", _C, _LOW, 5,
         "Image-only emails hide their text from filters, and are how QR-code phishing "
         "(quishing) is delivered.", ("T1566",)),
    Rule("CONTENT-TRACKING-PIXEL", "Tracking pixel", _C, _INFO, 0,
         "A 1x1 image tells the sender when the email is opened. Common in marketing, and the "
         "reason Dayag never loads remote images."),
    # Infrastructure -----------------------------------------------------
    Rule("INFRA-PHP-SCRIPT", "Sent by a script on a web server", _I, _MED, 15,
         "The X-PHP-Originating-Script header shows the email was sent by a PHP script, often "
         "on a hacked website.", ("T1584.004",)),
    Rule("INFRA-MAILER", "Mass-mailing software", _I, _LOW, 5,
         "The X-Mailer header names software popular with spammers and phishing kits."),
    Rule("INFRA-NO-MESSAGE-ID", "Missing Message-ID", _I, _LOW, 5,
         "Every normal mail server adds a Message-ID; its absence suggests a hand-rolled sending "
         "script."),
    Rule("INFRA-IP-REPUTATION", "Sending IP has abuse reports", _I, _HIGH, 30,
         "AbuseIPDB users have recently reported the IP that sent this email.", online=True),
    # Meta ---------------------------------------------------------------
    Rule("META-REPORTED", "Analysed the attached message", _M, _INFO, 0,
         "The file is a report wrapper, an email forwarded as an attachment, so the attached "
         "original was analysed instead."),
    Rule("META-LOOKUP-FAILED", "An online lookup failed", _M, _INFO, 0,
         "A reputation or registration lookup could not be completed. Results may be "
         "incomplete."),
)
# fmt: on

RULES: dict[str, Rule] = {rule.id: rule for rule in _RULES}
assert len(RULES) == len(_RULES), "duplicate rule id"


def get_rule(rule_id: str) -> Rule:
    return RULES[rule_id]


def detections_markdown() -> str:
    """Render the rule table as Markdown for docs/DETECTIONS.md."""
    lines = [
        "# Detections",
        "",
        "<!-- Generated by `dayag rules --markdown`. Do not edit by hand. -->",
        "",
        "Every finding Dayag can report. Points add up to the score (0-100), counting each rule "
        "once however many times it fires. Rules marked 🌐 only run with `--online`.",
        "",
        "| Verdict | Score |",
        "| --- | --- |",
        "| Malicious | 70-100 |",
        "| Likely phishing | 40-69 |",
        "| Suspicious | 15-39 |",
        "| No strong indicators | 0-14 |",
        "",
    ]
    for category in Category:
        rules = [r for r in _RULES if r.category is category]
        lines += [
            f"## {category.value.capitalize()}",
            "",
            "| ID | Finding | Severity | Points | ATT&CK | Why it matters |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for r in rules:
            attack = ", ".join(
                f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)"
                for t in r.attack
            )
            online = " 🌐" if r.online else ""
            lines.append(
                f"| `{r.id}` | {r.title}{online} | {r.severity.label} | {r.points:+d} | "
                f"{attack} | {r.rationale} |"
            )
        lines.append("")
    return "\n".join(lines)
