from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from spammaild.analyzers.content import SkopsLinearModel
from spammaild.main import create_app
from spammaild.parsing import ParsedEmail, parse_email
from spammaild.service import Analyzer
from spammaild.settings import DEFAULT_MODEL_PATH, Settings

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLES = Path(__file__).parents[1] / "spammaild" / "web" / "static" / "samples"
# EICAR test dizesi parça parça kurulur; dosyada tam hâli durmaz (antivirüs dosyayı silmesin).
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-" + b"TEST-FILE!$H+H*"


def make_settings(**overrides) -> Settings:
    values = {"trusted_authserv_id": "mx.google.com", "demo_mode": True, "allow_no_auth": True}
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture
def fixture_bytes():
    def _load(name: str) -> bytes:
        return (FIXTURES / name).read_bytes()

    return _load


@pytest.fixture
def parsed_fixture(fixture_bytes):
    def _parse(name: str) -> ParsedEmail:
        return parse_email(fixture_bytes(name))

    return _parse


@pytest.fixture(scope="session")
def content_model() -> SkopsLinearModel:
    return SkopsLinearModel(DEFAULT_MODEL_PATH)


@pytest.fixture
def make_client(content_model):
    clients: list[TestClient] = []

    def _make(**overrides) -> TestClient:
        settings = make_settings(**overrides)
        app = create_app(settings, analyzer=Analyzer(settings=settings, model=content_model))
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield _make
    for client in clients:
        client.__exit__(None, None, None)
