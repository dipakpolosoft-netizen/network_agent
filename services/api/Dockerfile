FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.lock ./
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock \
    && pip install --no-cache-dir --no-deps --no-build-isolation . \
    && groupadd --gid 10001 forgesec \
    && useradd --uid 10001 --gid forgesec --home-dir /nonexistent --no-create-home forgesec \
    && mkdir -p /var/lib/forgesec \
    && chown -R forgesec:forgesec /var/lib/forgesec

USER forgesec
EXPOSE 8000
CMD ["uvicorn", "forgesec_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
