#!/bin/bash

set -e

echo "Starting ClamAV daemon..."

# Start ClamAV daemon in the background
clamd &

# Store clamd PID for later
CLAMD_PID=$!

echo "Waiting for clamd socket to be ready..."

# Wait for clamd socket to be ready
for i in {1..30}; do
	if [ -S /var/run/clamav/clamd.ctl ]; then
		echo "✓ clamd socket is ready"
		break
	fi
	if [ $i -eq 30 ]; then
		echo "ERROR: clamd socket not ready after 30 seconds"
		exit 1
	fi
	echo "Waiting for clamd.ctl ($i/30)..."
	sleep 1
done

echo "Updating virus definitions..."

# Update virus definitions (run in background, don't block startup)
freshclam || echo "Warning: freshclam update failed (will retry later)"

echo "Starting NEXA..."

# Start the application
exec node ./dist/index.js
