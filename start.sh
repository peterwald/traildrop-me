#!/bin/sh

set -e

echo "Starting Tailscale daemon..."
tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
TAILSCALED_PID=$!

# Wait for tailscaled to start
sleep 2

echo "Authenticating with Tailscale..."
if [ -z "$TAILSCALE_AUTH_KEY" ]; then
    echo "ERROR: TAILSCALE_AUTH_KEY environment variable is not set"
    exit 1
fi

tailscale up --authkey="$TAILSCALE_AUTH_KEY" --hostname=taildrop-me

echo "Waiting for Tailscale to be ready..."
for i in $(seq 1 30); do
    if tailscale status > /dev/null 2>&1; then
        echo "Tailscale is ready!"
        break
    fi
    echo "Waiting for Tailscale... ($i/30)"
    sleep 1
done

if ! tailscale status > /dev/null 2>&1; then
    echo "ERROR: Tailscale failed to connect"
    exit 1
fi

echo "Tailscale status:"
tailscale status

echo "Starting Taildrop web application..."
exec ./taildrop-me
