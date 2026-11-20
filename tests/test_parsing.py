import pytest

from spammaild.parsing import ParseError, build_text_message, parse_email


def test_html_only_mail_gets_text_and_links(parsed_fixture):
    parsed = parsed_fixture("html_only.eml")
    assert "kazandınız" in parsed.text
    assert "color:red" not in parsed.text  # <style> içeriği atlanır
    assert parsed.subject == "Büyük indirim sizi bekliyor"
    assert [(link.href, link.text) for link in parsed.links] == [
        ("https://firsat-dunyasi.example/al", "Hediyeni al")
    ]


def test_multipart_alternative_keeps_html_links_and_plain_text(parsed_fixture):
    parsed = parsed_fixture("href_mismatch.eml")
    assert parsed.text.startswith("Sayın müşterimiz")
    assert parsed.links[0].text == "www.garantibbva.com.tr"
    assert parsed.links[0].source == "html"
    assert parsed.from_display == "Garanti BBVA"
    assert parsed.from_domain == "garanti-guvenlik.example"


def test_attachments_are_read_from_mime_parts(parsed_fixture):
    parsed = parsed_fixture("double_extension.eml")
    assert len(parsed.attachments) == 1
    attachment = parsed.attachments[0]
    assert attachment.filename == "fatura.pdf.exe"
    assert attachment.size > 0
    assert "faturanız" in parsed.text


def test_text_urls_are_extracted_without_trailing_punctuation(parsed_fixture):
    parsed = parsed_fixture("paypal_evil_link.eml")
    assert [link.href for link in parsed.links] == ["https://paypal.com.evil.io/login?id=123"]


def test_missing_subject_does_not_crash():
    parsed = parse_email(b"From: a@b.example\n\nGovde")
    assert parsed.subject == ""
    assert parsed.text.strip() == "Govde"


@pytest.mark.parametrize("raw", [b"", b"   \n  "])
def test_empty_input_raises(raw):
    with pytest.raises(ParseError):
        parse_email(raw)


def test_build_text_message_roundtrip():
    raw = build_text_message("Merhaba dünya", subject="Selam", sender="Ali <ali@ornek.example>")
    parsed = parse_email(raw)
    assert parsed.subject == "Selam"
    assert parsed.from_address == "ali@ornek.example"
    assert "Merhaba dünya" in parsed.text
