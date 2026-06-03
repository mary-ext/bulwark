#!/bin/sh
# Make /data writable by the runtime user, then drop privileges to run it.
#
# The image already chowns /data to `bulwark`, but a bind mount (e.g.
# `./data:/data` in compose) shadows that with the host dir's ownership — which
# is usually root, leaving the non-root process unable to create config/lists
# and crashing with EACCES. A named volume doesn't hit this (Docker seeds it
# from the image), so the example compose works either way.
set -e

if [ "$(id -u)" = "0" ]; then
    # Only chown when ownership is actually wrong, so a correctly-owned (and
    # possibly large) data dir isn't walked recursively on every restart.
    if [ "$(stat -c %u /data)" != "10001" ]; then
        chown -R bulwark:bulwark /data
    fi
    # gosu re-execs the binary as `bulwark`; its file capability
    # (cap_net_bind_service) is applied on exec, so :53 still binds non-root.
    exec gosu bulwark /usr/local/bin/bulwark "$@"
fi

# Already non-root (e.g. `docker run --user`): run directly, no chown possible.
exec /usr/local/bin/bulwark "$@"
