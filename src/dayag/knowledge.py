"""Reference data the checks rely on.

Kept in one module so it is easy to review and extend. Every list here is a
heuristic: it will miss things and occasionally match a legitimate email,
which is why Dayag explains and scores its findings instead of just blocking.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...]
    """Registrable domains the brand really sends from and hosts on."""
    labels: tuple[str, ...]
    """Distinctive domain labels attackers imitate (paypal, microsoft...)."""
    aliases: tuple[str, ...]
    """Names that appear in display names, lower case. Hebrew is matched as a substring."""


# fmt: off
# Free-mail domains (gmail.com, outlook.com...) are deliberately not listed
# as brand domains: "Microsoft Support <x@outlook.com>" is not Microsoft.
BRANDS: tuple[Brand, ...] = (
    Brand("PayPal", ("paypal.com", "paypal.me", "paypalobjects.com", "paypal-communication.com",
                     "paypal-community.com"), ("paypal",), ("paypal",)),
    Brand("Microsoft", ("microsoft.com", "microsoftonline.com", "office.com", "office365.com",
                        "office.net", "sharepoint.com", "onedrive.com", "onmicrosoft.com",
                        "microsoft365.com", "azure.com", "windows.net", "windows.com",
                        "skype.com", "bing.com", "msauth.net", "msftauth.net"),
              ("microsoft", "microsoft365", "office365", "m365", "microsoftonline", "outlook",
               "onedrive", "sharepoint"),
              ("microsoft", "office 365", "microsoft 365", "outlook", "onedrive", "sharepoint",
               "microsoft teams")),
    Brand("Apple", ("apple.com", "apple.news", "itunes.com"), ("apple", "icloud", "itunes"),
          ("apple", "icloud", "itunes", "app store")),
    Brand("Google", ("google.com", "youtube.com", "goo.gl", "g.co", "withgoogle.com"),
          ("google", "gmail"), ("google", "gmail", "google drive", "google docs")),
    Brand("Amazon", ("amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it",
                     "amazon.es", "amazon.ca", "amazon.co.jp", "amazon.in", "amazon.com.au",
                     "amazon.nl", "primevideo.com"), ("amazon",),
          ("amazon", "amazon prime", "prime video")),
    Brand("Netflix", ("netflix.com",), ("netflix",), ("netflix",)),
    Brand("Meta", ("facebook.com", "facebookmail.com", "facebook.net", "fb.com", "fbcdn.net",
                   "meta.com", "instagram.com", "whatsapp.com", "whatsapp.net"),
          ("facebook", "instagram", "whatsapp"), ("facebook", "meta", "instagram", "whatsapp")),
    Brand("LinkedIn", ("linkedin.com", "lnkd.in", "licdn.com"), ("linkedin",), ("linkedin",)),
    Brand("DHL", ("dhl.com", "dhl.de", "dpdhl.com"), ("dhl",), ("dhl",)),
    Brand("FedEx", ("fedex.com",), ("fedex",), ("fedex",)),
    Brand("UPS", ("ups.com",), ("ups",), ("ups",)),
    Brand("DocuSign", ("docusign.com", "docusign.net"), ("docusign",), ("docusign",)),
    Brand("Dropbox", ("dropbox.com", "dropboxmail.com", "dropboxusercontent.com"), ("dropbox",),
          ("dropbox",)),
    Brand("WeTransfer", ("wetransfer.com", "we.tl"), ("wetransfer",), ("wetransfer",)),
    Brand("Adobe", ("adobe.com", "adobesign.com"), ("adobe",), ("adobe", "adobe sign", "acrobat")),
    Brand("Zoom", ("zoom.us", "zoom.com"), ("zoom",), ("zoom",)),
    Brand("GitHub", ("github.com",), ("github",), ("github",)),
    Brand("Coinbase", ("coinbase.com",), ("coinbase",), ("coinbase",)),
    Brand("Binance", ("binance.com",), ("binance",), ("binance",)),
    Brand("MetaMask", ("metamask.io",), ("metamask",), ("metamask",)),
    Brand("Steam", ("steampowered.com", "steamcommunity.com"), ("steampowered", "steamcommunity"),
          ("steam support", "steam community")),
    Brand("Chase", ("chase.com", "jpmorgan.com", "jpmorganchase.com"), ("chase",),
          ("chase", "chase bank", "jpmorgan chase")),
    Brand("Wells Fargo", ("wellsfargo.com", "wf.com"), ("wellsfargo",), ("wells fargo",)),
    Brand("Bank of America", ("bankofamerica.com", "bofa.com"), ("bankofamerica",),
          ("bank of america",)),
    # Israel
    Brand("Israel Post", ("israelpost.co.il",), ("israelpost",), ("israel post", "דואר ישראל")),
    Brand("Bank Leumi", ("leumi.co.il", "bankleumi.co.il"), ("leumi", "bankleumi"),
          ("bank leumi", "בנק לאומי")),
    Brand("Bank Hapoalim", ("bankhapoalim.co.il", "poalim.co.il"), ("bankhapoalim", "hapoalim"),
          ("bank hapoalim", "hapoalim", "בנק הפועלים")),
    Brand("Discount Bank", ("discountbank.co.il",), ("discountbank",),
          ("discount bank", "בנק דיסקונט")),
    Brand("Isracard", ("isracard.co.il",), ("isracard",), ("isracard", "ישראכרט")),
    Brand("Israeli government", ("gov.il",), (),
          ("gov.il", "רשות המסים", "מס הכנסה", "ביטוח לאומי", "משרד הפנים", "משרד התחבורה")),
)

# Ordinary words one letter away from a brand label (apple/apply).
TYPO_EXCEPTIONS = frozenset({
    "apply", "apples", "ample", "abode", "adore", "chose", "chasm", "chased", "chaser", "chases",
    "chaste", "googly", "zooms", "fedexs",
})

FREEMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com",
    "msn.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "aol.com", "icloud.com", "me.com",
    "mac.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "gmx.de",
    "mail.com", "zoho.com", "zohomail.com", "yandex.com", "yandex.ru", "mail.ru",
    "tutanota.com", "tuta.io", "fastmail.com", "walla.co.il", "walla.com", "bezeqint.net",
    "netvision.net.il", "012.net.il",
})

# Large platforms whose names contain brand words but are not impersonations.
INFRASTRUCTURE_DOMAINS = frozenset({
    "amazonaws.com", "amazonses.com", "cloudfront.net", "googleusercontent.com",
    "googleapis.com", "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
    "googleadservices.com", "gstatic.com", "githubusercontent.com", "githubassets.com",
    "azureedge.net", "akamaihd.net", "outlook.office365.com",
})

URL_SHORTENERS = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id",
    "bl.ink", "short.io", "qrco.de", "lnkd.in", "shorturl.gg", "tiny.one", "u.to",
})

# Free hosting, file sharing and "deploy in a minute" platforms. Legitimate,
# but a reputable domain on a phishing page is exactly what attackers want.
FREE_HOSTING = frozenset({
    "web.app", "firebaseapp.com", "firebasestorage.googleapis.com", "storage.googleapis.com",
    "netlify.app", "vercel.app", "pages.dev", "workers.dev", "r2.dev", "glitch.me",
    "github.io", "gitlab.io", "herokuapp.com", "onrender.com", "replit.app", "repl.co",
    "weebly.com", "wixsite.com", "square.site", "webflow.io", "000webhostapp.com",
    "blogspot.com", "sites.google.com", "forms.gle", "s3.amazonaws.com", "amplifyapp.com",
    "blob.core.windows.net", "web.core.windows.net", "azurewebsites.net", "ngrok-free.app",
    "ngrok.io", "ngrok.app", "trycloudflare.com", "surge.sh", "notion.site", "framer.website",
    "canva.site", "godaddysites.com", "jimdosite.com", "mystrikingly.com",
    "dropboxusercontent.com", "1drv.ms", "codepen.io", "jsfiddle.net",
})

IPFS_GATEWAYS = frozenset({
    "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "gateway.pinata.cloud", "nftstorage.link",
    "w3s.link", "4everland.io", "ipfs.w3s.link", "fleek.co",
})

# Email service providers' click-tracking domains: a link text/target mismatch
# through these is how every newsletter works, so it is not reported.
CLICK_TRACKERS = frozenset({
    "list-manage.com", "mailchimp.com", "sendgrid.net", "mandrillapp.com", "hubspotlinks.com",
    "hubspotemail.net", "exacttarget.com", "rs6.net", "mailgun.org", "awstrack.me",
    "sparkpostmail.com", "mjt.lu", "klclick.com", "klclick1.com", "aweber.com",
    "constantcontact.com", "createsend1.com", "cmail19.com", "cmail20.com", "mlsend.com",
    "brevo.com", "sendibt3.com", "salesforce.com",
})

# Based on abuse statistics published by Spamhaus and Interisle.
RISKY_TLDS = frozenset({
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "icu", "cam", "rest", "buzz",
    "monster", "sbs", "cfd", "quest", "bond", "cyou", "click", "country", "kim", "work", "loan",
    "men", "mom", "date", "faith", "racing", "review", "win", "party", "stream", "gdn", "lol",
})

EXECUTABLE_EXTENSIONS = frozenset({
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf",
    "wsh", "ws", "hta", "msi", "msix", "msixbundle", "appx", "appxbundle", "appinstaller", "jar",
    "lnk", "cpl", "reg", "dll", "scf", "url", "xll", "iqy", "slk", "chm", "inf", "msc",
    "settingcontent-ms", "application", "gadget", "sh", "command", "apk", "dmg", "pkg",
})
DISK_IMAGE_EXTENSIONS = frozenset({"iso", "img", "vhd", "vhdx"})
ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "gz", "tar", "tgz", "cab", "ace", "arj",
                                "bz2", "xz", "zipx", "z"})
MACRO_EXTENSIONS = frozenset({"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam",
                              "ppsm", "sldm"})
HTML_EXTENSIONS = frozenset({"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"})
ONENOTE_EXTENSIONS = frozenset({"one", "onepkg"})
# Extensions an attacker puts before the real one to make a file look harmless.
DECOY_EXTENSIONS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf",
                              "csv", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "odt", "wav"})

# What each extension's content should look like, by detected file kind.
EXPECTED_KINDS: dict[str, frozenset[str]] = {
    "pdf": frozenset({"pdf"}),
    "doc": frozenset({"ole"}), "xls": frozenset({"ole"}), "ppt": frozenset({"ole"}),
    "msg": frozenset({"ole"}),
    **{ext: frozenset({"ooxml"}) for ext in ("docx", "xlsx", "pptx", "docm", "xlsm", "pptm",
                                             "dotx", "dotm", "xltx", "xltm", "potx", "ppsx")},
    "zip": frozenset({"zip", "ooxml", "jar"}),
    "jpg": frozenset({"jpeg"}), "jpeg": frozenset({"jpeg"}), "png": frozenset({"png"}),
    "gif": frozenset({"gif"}),
    "html": frozenset({"html"}), "htm": frozenset({"html"}), "svg": frozenset({"svg", "html"}),
    "rtf": frozenset({"rtf"}), "iso": frozenset({"iso"}), "rar": frozenset({"rar"}),
    "7z": frozenset({"7z"}), "gz": frozenset({"gzip"}), "exe": frozenset({"pe"}),
    "dll": frozenset({"pe"}), "scr": frozenset({"pe"}), "lnk": frozenset({"lnk"}),
    "one": frozenset({"onenote"}), "txt": frozenset({"text"}), "csv": frozenset({"text"}),
}
EXECUTABLE_KINDS = frozenset({"pe", "elf", "macho", "lnk", "script"})

MAILER_SOFTWARE = ("leaf phpmailer", "phpmailer", "sendblaster", "atomic mail sender",
                   "gammadyne", "turbo-mailer", "supermailer", "mailking", "massmail")

# Phrase lists per content rule. English phrases match on word boundaries;
# Hebrew phrases match as substrings because Hebrew attaches prefixes (ו, ה,
# ב, ל, מ, ש) directly to words.
PHRASES: dict[str, tuple[str, ...]] = {
    "CONTENT-URGENCY": (
        "urgent", "urgently", "immediately", "as soon as possible", "within 24 hours",
        "within 48 hours", "act now", "final notice", "final warning", "last chance",
        "expires today", "will be suspended", "will be closed", "will be deactivated",
        "will be deleted", "has been suspended", "has been locked", "has been limited",
        "unusual activity", "unusual sign-in", "suspicious activity", "action required",
        "immediate action", "failure to comply",
        "דחוף", "באופן מיידי", "תוך 24 שעות", "תוך 48 שעות", "הודעה אחרונה", "התראה אחרונה",
        "יושעה", "ייחסם", "ייסגר", "פעילות חריגה", "פעולה נדרשת", "יוחזר לשולח",
        "תוחזר לשולח",
    ),
    "CONTENT-CREDENTIALS": (
        "verify your account", "confirm your account", "verify your identity",
        "confirm your identity", "update your password", "reset your password",
        "password expires", "password will expire", "keep my current password",
        "login to your account", "log in to your account", "sign in to your account",
        "validate your", "re-enter your", "confirm your details", "update your payment",
        "update your billing", "security check", "verify your email",
        "אמת את", "אימות חשבון", "אשר את פרטי", "עדכן את פרטי", "עדכון פרטי", "הסיסמה שלך",
        "התחבר לחשבון", "היכנס לחשבון", "פרטי כרטיס", "פרטי האשראי",
    ),
    "CONTENT-PAYMENT": (
        "wire transfer", "bank transfer", "new bank account", "bank details",
        "change of bank", "updated banking", "outstanding invoice", "overdue invoice",
        "payment failed", "payment overdue", "unpaid", "remittance", "customs fee",
        "delivery fee", "shipping fee", "keep this confidential", "are you available",
        "quick favor", "process a payment",
        "העברה בנקאית", "פרטי חשבון בנק", "חשבון בנק חדש", "תשלום נכשל", "דמי משלוח",
        "דמי מכס", "חוב פתוח", "חשבונית לתשלום", "להסדיר תשלום", "להסדרת התשלום",
    ),
    "CONTENT-GIFT-CARD": (
        "gift card", "gift cards", "itunes card", "google play card", "steam card",
        "amazon card", "scratch the back", "כרטיס מתנה", "כרטיסי מתנה", "גיפט קארד",
    ),
    "CONTENT-GENERIC-GREETING": (
        "dear customer", "dear user", "dear client", "dear valued", "dear account holder",
        "dear member", "dear sir/madam", "dear sir or madam", "hello user",
        "לקוח יקר", "לקוחה יקרה", "לקוח/ה יקר/ה", "משתמש יקר",
    ),
}
# fmt: on
