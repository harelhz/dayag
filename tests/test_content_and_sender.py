from __future__ import annotations

from conftest import build_email, ids, run

ZWSP = "\N{ZERO WIDTH SPACE}"


def test_display_name_brand_impersonation() -> None:
    report = run(build_email({"From": '"PayPal Support" <help@random-shop.example>'}))
    assert "SENDER-DISPLAY-BRAND" in ids(report)


def test_brand_display_name_from_the_brand_is_fine() -> None:
    report = run(build_email({"From": '"PayPal" <service@paypal.com>'}))
    assert "SENDER-DISPLAY-BRAND" not in ids(report)


def test_hebrew_display_name() -> None:
    report = run(build_email({"From": '"בנק הפועלים" <info@secure-update.example>'}))
    assert "SENDER-DISPLAY-BRAND" in ids(report)


def test_display_name_with_other_address() -> None:
    report = run(build_email({"From": '"ceo@contoso.com" <ceo.contoso@gmail.com>'}))
    assert {"SENDER-DISPLAY-ADDRESS", "SENDER-FREEMAIL"} <= ids(report)


def test_reply_to_rules() -> None:
    report = run(build_email({"Reply-To": "billing@other-company.example"}))
    assert "SENDER-REPLYTO-MISMATCH" in ids(report)
    report = run(build_email({"Reply-To": "alice.levi.private@gmail.com"}))
    assert "SENDER-REPLYTO-FREEMAIL" in ids(report)
    assert "SENDER-REPLYTO-MISMATCH" not in ids(report)


def test_reply_to_same_address_is_fine() -> None:
    report = run(build_email({"Reply-To": "alice@contoso.com"}))
    assert not {i for i in ids(report) if i.startswith("SENDER-REPLYTO")}


def test_lookalike_sender() -> None:
    report = run(build_email({"From": "security@paypa1.com"}))
    assert "SENDER-LOOKALIKE" in ids(report)


def test_encoded_display_name_with_comma() -> None:
    # Built by hand: Python's own serializer would drop the quotes.
    raw = b"From: =?utf-8?b?TGV2aSwgQWxpY2U=?= <alice@contoso.com>\r\nSubject: x\r\n\r\nHi\r\n"
    assert run(raw).summary.sender == '"Levi, Alice" <alice@contoso.com>'


def test_unquoted_comma_in_display_name_picks_the_real_address() -> None:
    raw = b"From: Levi, Alice <alice@contoso.com>\r\nSubject: x\r\n\r\nHi\r\n"
    assert run(raw).summary.sender.endswith("<alice@contoso.com>")


def test_phrases_english_and_hebrew() -> None:
    report = run(
        build_email(
            text="Dear customer, verify your account immediately or it "
            "will be suspended. Please buy gift cards."
        )
    )
    assert {
        "CONTENT-GENERIC-GREETING",
        "CONTENT-CREDENTIALS",
        "CONTENT-URGENCY",
        "CONTENT-GIFT-CARD",
    } <= ids(report)
    report = run(build_email(text="לקוח יקר, יש להסדיר תשלום דמי משלוח באופן מיידי."))
    assert {"CONTENT-GENERIC-GREETING", "CONTENT-PAYMENT", "CONTENT-URGENCY"} <= ids(report)


def test_phrases_survive_zero_width_characters() -> None:
    report = run(build_email(text=f"Please ver{ZWSP}ify your acc{ZWSP}ount."))
    assert "CONTENT-CREDENTIALS" in ids(report)


def test_english_phrases_need_word_boundaries() -> None:
    report = run(build_email(text="The blocked unlocked padlock was urgentish."))
    assert "CONTENT-URGENCY" not in ids(report)


def test_fake_reply() -> None:
    assert "CONTENT-FAKE-REPLY" in ids(run(build_email({"Subject": "RE: invoice"})))
    threaded = build_email({"Subject": "RE: invoice", "In-Reply-To": "<x@contoso.com>"})
    assert "CONTENT-FAKE-REPLY" not in ids(run(threaded))


def test_hidden_text_and_image_only() -> None:
    hidden = '<div style="display:none">' + "lorem ipsum " * 30 + "</div><p>Hi</p>"
    assert "CONTENT-HIDDEN-TEXT" in ids(run(build_email(text=None, html=hidden)))
    image_only = '<img src="cid:qr" width="300" height="300"><p>Scan me</p>'
    assert "CONTENT-IMAGE-ONLY" in ids(run(build_email(text=None, html=image_only)))


def test_script_in_body() -> None:
    report = run(build_email(text=None, html="<p>Hi</p><script>steal()</script>"))
    assert "CONTENT-SCRIPT" in ids(report)
    assert "steal" not in report.body_preview


def test_infrastructure_headers() -> None:
    report = run(
        build_email(
            {"X-Mailer": "Leaf PHPMailer 2.8", "X-PHP-Originating-Script": "33:wp-content/x.php"},
            drop=["Message-ID"],
        )
    )
    assert {"INFRA-MAILER", "INFRA-PHP-SCRIPT", "INFRA-NO-MESSAGE-ID"} <= ids(report)


def test_malformed_email_does_not_crash() -> None:
    raw = (
        b"From: <<<broken@@\r\nSubject: =?bogus?q?x?=\r\nContent-Type: multipart/mixed; "
        b'boundary="b"\r\n\r\n--b\r\nContent-Type: text/html; charset=no-such-charset\r\n\r\n'
        b"<a href='http://[::1'>x</a>\r\n--b--"
    )
    report = run(raw)
    assert report.verdict is not None
