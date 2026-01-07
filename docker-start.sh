#!/bin/bash

set -e

# Start ClamAV daemon in the background
clamd &

echo "Refreshing virus definitions..."

# Update virus definitions
freshclam

echo "Starting NEXA..."

# Start the application
exec node ./dist/index.js

echo "Goodbye!"
