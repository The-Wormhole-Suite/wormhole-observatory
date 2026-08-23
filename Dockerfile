FROM python:3.11.16-slim-bookworm@sha256:2e32f7d302adc1c37428355c1e646897c0c53f4fd60b6a551245fb90ee129f91

LABEL org.opencontainers.image.source="https://github.com/The-Wormhole-Suite/wormhole-observatory" \
      org.opencontainers.image.title="Wormhole Observatory" \
      org.opencontainers.image.description="Headless Wormhole Observatory Web/API service"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIHOLE_MANAGER_HOME=/data/wormhole \
    WORMHOLE_BIND_HOST=0.0.0.0 \
    WORMHOLE_PORT=8765 \
    WORMHOLE_ACCESS_MODE=lan_tailscale

WORKDIR /app

COPY pyproject.toml README.md ./
COPY pihole_manager ./pihole_manager
COPY pihole6api ./pihole6api

RUN python -m pip install --no-cache-dir . \
    && groupadd --system --gid 10001 wormhole \
    && useradd --system --uid 10001 --gid wormhole --home-dir /nonexistent \
        --shell /usr/sbin/nologin wormhole \
    && mkdir -p /data/wormhole \
    && chown -R wormhole:wormhole /data

USER wormhole
VOLUME ["/data"]
EXPOSE 8765
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,socket; s=socket.create_connection(('127.0.0.1',int(os.environ.get('WORMHOLE_PORT','8765'))),3); s.close()"

ENTRYPOINT ["python", "-m", "pihole_manager.headless"]
