# ────────────────────────────────────────────────────────────────────
# 1. Build stage – install Python deps into a writable layer
# ────────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder
WORKDIR /build

RUN pip install --no-cache-dir \
        fastapi \
        uvicorn[standard] \
        pyjwt \
        cryptography \
        httpx \
        cachetools \
        python-multipart

# ────────────────────────────────────────────────────────────────────
# 2. Runtime image – copy only the needed bits from stage 1
# ────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # default listening port
    BRIDGE_PORT=80

COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=builder /usr/local/bin /usr/local/bin

WORKDIR /srv
COPY bridge_idp.py .
#COPY idp-private.pem .

EXPOSE ${BRIDGE_PORT}

# ────────────────────────────────────────────────────────────────────
# 3. Entrypoint – start uvicorn with live‑reload disabled
# ────────────────────────────────────────────────────────────────────
CMD ["sh", "-c", \
     "uvicorn bridge_idp:app \
        --host 0.0.0.0 --port ${BRIDGE_PORT} --no-access-log" ]

