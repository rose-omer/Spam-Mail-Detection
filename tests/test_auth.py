from spammaild.analyzers.auth import analyze_auth, read_trusted_results

TRUSTED = "mx.google.com"


def _names(signals):
    return {signal.name for signal in signals}


def test_clean_mail_reads_trusted_header(parsed_fixture):
    signals, report = analyze_auth(parsed_fixture("clean.eml"), TRUSTED)
    assert (report.spf.result, report.dkim.result, report.dmarc.result) == ("pass",) * 3
    assert report.spf.source == "Authentication-Results: mx.google.com"
    assert "auth_all_pass" in _names(signals)


def test_only_topmost_trusted_header_is_used(parsed_fixture):
    # İkinci (alttaki) başlık "pass" diyor; en üstteki güvenilen başlık "fail" diyor.
    report = read_trusted_results(parsed_fixture("fake_auth_results.eml"), TRUSTED)
    assert report.spf.result == "fail"
    assert report.dmarc.result == "fail"
    assert report.dkim.result == "none"


def test_forged_trusted_header_below_untrusted_top_is_ignored():
    from spammaild.parsing import parse_email

    # Alıcı sunucu kendi başlığını eklememiş; en üstte başka sunucu, altta saldırganın
    # yazdığı "mx.google.com" başlığı var. Alttaki başlık okunmamalı.
    raw = (
        b"Authentication-Results: relay.example; spf=none smtp.mailfrom=paypal.com\n"
        b"Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=paypal.com; "
        b"dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com\n"
        b"From: PayPal <service@paypal.com>\nSubject: x\n\nmerhaba"
    )
    signals, report = analyze_auth(parse_email(raw), TRUSTED)
    assert report.trusted_header_found is False
    assert report.spf.result == "unknown"
    assert "auth_all_pass" not in _names(signals)
    assert "auth_untrusted" in _names(signals)


def test_x_note_and_untrusted_authserv_id_do_not_pass(parsed_fixture):
    signals, report = analyze_auth(parsed_fixture("x_note_spoof.eml"), TRUSTED)
    assert report.trusted_header_found is False
    assert {report.spf.result, report.dkim.result, report.dmarc.result} == {"unknown"}
    assert "auth_all_pass" not in _names(signals)
    assert "auth_untrusted" in _names(signals)


def test_without_trusted_id_nothing_is_read(parsed_fixture):
    signals, report = analyze_auth(parsed_fixture("clean.eml"), "")
    assert report.spf.result == "unknown"
    untrusted = [signal for signal in signals if signal.name == "auth_untrusted"]
    assert untrusted and untrusted[0].status == "unknown"


def test_display_name_brand_spoof(parsed_fixture):
    signals, _ = analyze_auth(parsed_fixture("x_note_spoof.eml"), TRUSTED)
    assert "display_name_spoof" in _names(signals)


def test_real_brand_domain_is_not_spoof(parsed_fixture):
    signals, _ = analyze_auth(parsed_fixture("paypal_evil_link.eml"), TRUSTED)
    assert "display_name_spoof" not in _names(signals)


def test_dkim_domain_misaligned_with_from():
    from spammaild.parsing import parse_email

    raw = (
        b"Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=a@shop.example; "
        b"dkim=pass header.d=bulk-mailer.example; dmarc=pass header.from=shop.example\n"
        b"From: Shop <info@shop.example>\nSubject: x\n\nmerhaba"
    )
    signals, report = analyze_auth(parse_email(raw), TRUSTED)
    assert report.dkim_domain == "bulk-mailer.example"
    assert "auth_dkim_misaligned" in _names(signals)
