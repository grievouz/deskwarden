#!/usr/bin/env bash
# Runs a throwaway Vaultwarden (in-memory, signups open) on 127.0.0.1 for the
# DeskwardenAccount integration tests.
#
#   scripts/vaultwarden.sh start|stop
#
# Then: DESKWARDEN_TEST_SERVER=http://127.0.0.1:8222 swift test
set -euo pipefail

NAME=deskwarden-vaultwarden
IMAGE=vaultwarden/server:1.37.4
PORT="${DESKWARDEN_VAULTWARDEN_PORT:-8222}"

case "${1:-}" in
  start)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    # Tests log in several times a run; lift the login rate limit.
    docker run -d --name "$NAME" -p "127.0.0.1:$PORT:80" --tmpfs /data \
      -e SIGNUPS_ALLOWED=true -e DOMAIN="http://127.0.0.1:$PORT" \
      -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=1000 "$IMAGE" >/dev/null
    for _ in $(seq 1 60); do
      curl -fsS "http://127.0.0.1:$PORT/alive" >/dev/null 2>&1 && break
      sleep 0.5
    done
    echo "Vaultwarden on http://127.0.0.1:$PORT"
    ;;
  stop)
    docker rm -f "$NAME" >/dev/null
    ;;
  *)
    echo "usage: $0 start|stop" >&2
    exit 64
    ;;
esac
