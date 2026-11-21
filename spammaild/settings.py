"""Uygulama ayarları. Tek kaynak: ortam değişkenleri ve isteğe bağlı `.env` dosyası."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL_PATH = PACKAGE_DIR.parent / "models" / "legacy-lr"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Güvenlik katmanı. API_KEY boşsa sunucu başlamaz; yalnız yerel geliştirmede
    # ALLOW_NO_AUTH=true ile anahtarsız açılır.
    api_key: SecretStr | None = None
    allow_no_auth: bool = False
    rate_limit_per_minute: int = 30
    max_request_mb: float = 70.0  # yalnız /v1/analyze (ekli ham mail)
    max_text_request_mb: float = 2.0  # diğer bütün yollar (/v1/analyze/text dahil)
    max_attachment_mb: float = 25.0
    max_total_attachments_mb: float = 50.0

    # Dış servisler. DEMO_MODE açıkken hepsi kapalıdır.
    demo_mode: bool = False
    trusted_authserv_id: str = ""
    vt_api_key: SecretStr | None = None
    vt_upload: bool = False
    vt_poll_attempts: int = 3  # yüklemeden sonra analiz sonucunu en çok bu kadar sor
    vt_poll_interval_s: float = 5.0
    urlhaus_auth_key: SecretStr | None = None
    openphish_feed_path: Path | None = None
    clamd_host: str = ""
    clamd_port: int = 3310
    external_timeout_s: float = 8.0

    # İçerik modeli
    model_backend: str = "legacy-lr"
    model_path: Path = DEFAULT_MODEL_PATH
    transformer_model_name: str = "jhu-clsp/mmBERT-base"

    @property
    def max_request_bytes(self) -> int:
        return int(self.max_request_mb * 1024 * 1024)

    @property
    def max_text_request_bytes(self) -> int:
        return int(self.max_text_request_mb * 1024 * 1024)

    @property
    def max_attachment_bytes(self) -> int:
        return int(self.max_attachment_mb * 1024 * 1024)

    @property
    def max_total_attachment_bytes(self) -> int:
        return int(self.max_total_attachments_mb * 1024 * 1024)

    @property
    def auth_required(self) -> bool:
        return bool(self.api_key and self.api_key.get_secret_value())


@lru_cache
def get_settings() -> Settings:
    return Settings()
