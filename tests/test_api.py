import pytest

from spammaild.api.security import RateLimiter
from tests.conftest import SAMPLES


def test_rate_limiter_drops_expired_buckets():
    limiter = RateLimiter(limit_per_minute=5, window_s=60, sweep_every=4)
    for index in range(3):
        assert limiter.allow(f"10.0.0.{index}", now=0.0)
    assert len(limiter) == 3
    limiter.allow("10.0.0.9", now=120.0)  # 4. çağrı: süresi dolan kovalar silinir
    assert len(limiter) == 1


def test_health(make_client):
    response = make_client().get("/health")
    assert response.json() == {"status": "ok", "model": True}


def test_missing_api_key_is_401(make_client, fixture_bytes):
    client = make_client(api_key="gizli-test-anahtari")
    response = client.post(
        "/v1/analyze",
        content=fixture_bytes("clean.eml"),
        headers={"Content-Type": "message/rfc822"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"
    wrong = client.post("/v1/analyze", content=b"x", headers={"X-API-Key": "yanlis"})
    assert wrong.status_code == 401


def test_valid_api_key_is_200(make_client, fixture_bytes):
    client = make_client(api_key="gizli-test-anahtari")
    response = client.post(
        "/v1/analyze",
        content=fixture_bytes("clean.eml"),
        headers={"Content-Type": "message/rfc822", "X-API-Key": "gizli-test-anahtari"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["band"] == "clean"
    assert body["reasons"]
    assert body["auth"]["spf"]["result"] == "pass"


def test_large_body_is_413(make_client):
    client = make_client(max_request_mb=0.01)
    response = client.post("/v1/analyze", content=b"a" * 20_000)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_empty_body_is_422(make_client):
    response = make_client().post("/v1/analyze", content=b"")
    assert response.status_code == 422


@pytest.mark.parametrize(
    "body",
    [b'{"a":1}', b"X-Foo: bar\n\n", b"\n\n   \n", b"Received: from x\n\n \t\n"],
)
def test_non_mail_input_is_422_not_clean(make_client, body):
    # Skorlanamayan girdi "temiz" dönmemeli (fail-closed).
    response = make_client().post(
        "/v1/analyze", content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_whitespace_text_is_422(make_client):
    response = make_client().post("/v1/analyze/text", json={"text": "   "})
    assert response.status_code == 422


def test_missing_api_key_refuses_to_start():
    from spammaild.main import create_app
    from tests.conftest import make_settings

    with pytest.raises(RuntimeError, match="ALLOW_NO_AUTH"):
        create_app(make_settings(allow_no_auth=False))


def test_text_endpoint_checks_key_before_reading_body(make_client):
    client = make_client(api_key="gizli-test-anahtari")
    # Geçersiz JSON gövde; anahtar yok. Gövde okunmadan 401 dönmeli (422 değil).
    response = client.post(
        "/v1/analyze/text", content=b"{bozuk", headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 401


def test_text_endpoint_has_small_body_limit(make_client):
    client = make_client(max_text_request_mb=0.01)
    response = client.post("/v1/analyze/text", json={"text": "a" * 20_000})
    assert response.status_code == 413
    # Ham mail uç noktası büyük sınırı korur.
    raw = b"From: a@b.example\nSubject: x\n\n" + b"a" * 20_000
    assert client.post("/v1/analyze", content=raw).status_code == 200


def test_text_endpoint_invalid_json_is_422(make_client):
    response = make_client().post(
        "/v1/analyze/text", content=b"{bozuk", headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_multipart_eml_upload(make_client, fixture_bytes):
    response = make_client().post(
        "/v1/analyze",
        files={"file": ("ek.eml", fixture_bytes("double_extension.eml"), "message/rfc822")},
    )
    assert response.status_code == 200
    attachments = response.json()["attachments"]
    assert attachments[0]["filename"] == "fatura.pdf.exe"
    assert attachments[0]["clamav"]["status"] == "skipped"  # demo modu


def test_multipart_without_fields_is_422(make_client):
    response = make_client().post("/v1/analyze", files={"baska": ("a.txt", b"x")})
    assert response.status_code == 422


def test_text_endpoint(make_client):
    response = make_client().post(
        "/v1/analyze/text",
        json={"text": "Tebrikler! Ücretsiz hediye kazandınız, hemen tıklayın.", "subject": "Ödül"},
    )
    assert response.status_code == 200
    assert response.json()["message"]["language"] == "tr"


def test_text_endpoint_validation(make_client):
    response = make_client().post("/v1/analyze/text", json={"text": ""})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_rate_limit(make_client):
    client = make_client(rate_limit_per_minute=2)
    statuses = [
        client.post("/v1/analyze/text", json={"text": "merhaba"}).status_code for _ in range(3)
    ]
    assert statuses == [200, 200, 429]


def test_every_sample_has_reason_and_fake_bank_is_spam(make_client):
    client = make_client()
    for sample in SAMPLES.glob("*.eml"):
        response = client.post("/v1/analyze", content=sample.read_bytes())
        assert response.status_code == 200, sample.name
        assert response.json()["reasons"], sample.name
    bank = client.post("/v1/analyze", content=(SAMPLES / "sahte-banka.eml").read_bytes()).json()
    assert bank["band"] == "spam"
    clean = client.post("/v1/analyze", content=(SAMPLES / "temiz.eml").read_bytes()).json()
    assert clean["band"] == "clean"


def test_config_reports_demo_mode(make_client):
    body = make_client().get("/v1/config").json()
    assert body["demo_mode"] is True
    assert body["clamav_enabled"] is False
    assert body["vt_upload"] is False


def test_panel_and_docs(make_client):
    client = make_client()
    panel = client.get("/")
    assert panel.status_code == 200
    assert "default-src 'self'" in panel.headers["content-security-policy"]
    assert 'aria-live="polite"' in panel.text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/docs").status_code == 200
    assert "/v1/analyze" in client.get("/openapi.json").json()["paths"]
