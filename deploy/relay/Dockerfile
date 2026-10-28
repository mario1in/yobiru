# Yobiru relay (relay-v1, docs/RELAY_DESIGN.md) as a container, for example on Coolify.
# Build from the repository root:  docker build -f deploy/relay/Dockerfile -t yobiru-relay .
# The relay listens on 7790 inside the container only; put your platform's HTTPS proxy in front of it and
# keep /data on a persistent volume (it holds the enrolled devices, never messages).
FROM python:3.12-slim

RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin relay \
    && install -d -o relay -g relay -m 700 /data
WORKDIR /app
COPY relay.py /app/relay.py
COPY public_bots/bot_e2e.py /app/public_bots/bot_e2e.py
COPY deploy/relay/entrypoint.sh /app/entrypoint.sh

USER relay
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 7790
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD python3 -c "import sys, urllib.request; \
sys.exit(urllib.request.urlopen('http://127.0.0.1:7790/v1/health', timeout=4).status != 200)"
ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
