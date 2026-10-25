#!/bin/sh
set -eu

ALLOW_FILE=/etc/squid/robinhood-endpoints.allow
POLICY_FILE=/etc/rsa-egress/nftables.conf

# This first appliance release intentionally has one exact destination. Policy
# expansion requires changing both the reviewed inventory and this assertion.
if [ "$(wc -l < "$ALLOW_FILE" | tr -d ' ')" != 1 ] || [ "$(cat "$ALLOW_FILE")" != api.robinhood.com ]; then
    echo "Refusing to start: unexpected Robinhood endpoint allowlist" >&2
    exit 1
fi

nft delete table inet rsa_egress 2>/dev/null || true
nft -f "$POLICY_FILE"
nft list chain inet rsa_egress output >/dev/null

# Squid needs no privilege: its listener is unprivileged and all writable paths
# are tmpfs mounts. Remove every inherited capability before starting it.
exec setpriv \
    --reuid=10002 \
    --regid=10002 \
    --clear-groups \
    --inh-caps=-all \
    --ambient-caps=-all \
    --bounding-set=-all \
    /usr/sbin/squid -N -f /etc/squid/squid.conf
