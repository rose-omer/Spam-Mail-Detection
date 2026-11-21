"""Gerçek clamd ile EICAR taraması. CI'da `integration` işi ClamAV servisiyle koşar.

Yerelde: `CLAMD_HOST=127.0.0.1 pytest -m integration` (clamd çalışıyor olmalı).
"""

import asyncio
import os

import pytest

from spammaild.clients.http import ScanStatus
from spammaild.clients.scanners import ClamdScanner
from tests.conftest import EICAR

pytestmark = pytest.mark.integration
CLAMD_HOST = os.environ.get("CLAMD_HOST", "")


@pytest.mark.skipif(not CLAMD_HOST, reason="CLAMD_HOST tanımlı değil")
def test_eicar_is_infected_on_real_clamd():
    scanner = ClamdScanner(CLAMD_HOST, int(os.environ.get("CLAMD_PORT", "3310")))
    assert asyncio.run(scanner.scan(EICAR)).status == ScanStatus.INFECTED
    assert asyncio.run(scanner.scan(b"temiz icerik")).status == ScanStatus.CLEAN
