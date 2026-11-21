# syntax=docker/dockerfile:1.7
FROM python:3.14-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
# Sanal ortam son aşamayla aynı yolda kurulur (betik shebang yolları bozulmasın).
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.13.9 /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
# Yalnız bağımlılıklar kurulur; uygulama kodu son aşamada /app altına kopyalanır.
RUN uv sync --locked --no-dev --no-install-project

FROM python:3.14-slim
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY --from=build --chown=app:app /app/.venv /app/.venv
COPY --chown=app:app spammaild ./spammaild
COPY --chown=app:app models/legacy-lr ./models/legacy-lr
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    MODEL_PATH=/app/models/legacy-lr
USER app
EXPOSE 8100
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8100/health', timeout=2)"
CMD ["uvicorn", "spammaild.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8100", "--proxy-headers"]
