# syntax=docker/dockerfile:1

# ---- build stage: install locked, hash-verified dependencies into a venv ----
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
COPY requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --require-hashes --no-deps -r /tmp/requirements.txt

# ---- runtime stage ----
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    APP_DATABASE_PATH=/data/app.db \
    FORWARDED_ALLOW_IPS=127.0.0.1

RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data && chown app:app /data && chmod 700 /data

COPY --from=build /opt/venv /opt/venv
# Code is owned by root and read-only for the app user.
COPY app /srv/app

WORKDIR /srv
USER app
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT', '8000'), timeout=3).status == 200 else 1)"]

# Exactly one worker: login rate limiting is kept in process memory.
# PORT is set by platforms such as Render; defaults to 8000.
CMD ["sh", "-c", "exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port \"${PORT:-8000}\" --workers 1 --proxy-headers --no-server-header --no-date-header --limit-concurrency 64 --timeout-keep-alive 5"]
