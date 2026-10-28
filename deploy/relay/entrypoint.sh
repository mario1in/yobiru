#!/bin/sh
# First start: create the relay's state in the persistent volume. Later starts reuse it unchanged, so
# enrolled devices survive redeploys. Inside a container the relay binds 0.0.0.0; publish no host port.
set -eu
RELAY_HOME="${RELAY_HOME:-/data}"
if [ ! -f "$RELAY_HOME/relay.json" ]; then
    python3 /app/relay.py server init --relay-home "$RELAY_HOME" --bind 0.0.0.0 --port 7790
fi
exec python3 /app/relay.py server serve --relay-home "$RELAY_HOME"
