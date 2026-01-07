#!/bin/bash

set -e

# Start ClamAV daemon in the background
clamd &

echo "Refreshing virus definitions..."

# Update virus definitions
freshclam

echo "Starting NEXA..."

# Wait for clamd socket to be ready
echo "Waiting for clamd to be ready..."
for i in {1..30}; do
	if [ -S /var/run/clamav/clamd.ctl ]; then
		echo "clamd is ready."
		break
	fi
	echo "clamd.ctl not found, retrying ($i/30)..."
	sleep 1
done

# Start the application
exec node ./dist/index.js

echo "Goodbye!"
