#!/bin/sh
# Repair bind-mount ownership, then drop privileges.
set -e

if [ "$(id -u)" = "0" ]; then
    # Avoid walking an already-correct data directory.
    if [ "$(stat -c %u /data)" != "10001" ]; then
        chown -R bulwark:bulwark /data
    fi
    exec gosu bulwark /usr/local/bin/bulwark "$@"
fi

# Custom non-root user.
exec /usr/local/bin/bulwark "$@"
