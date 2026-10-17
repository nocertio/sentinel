#!/bin/sh
set -e

# postinst also fires on dpkg's abort-* recovery paths; only configure needs this.
if [ "$1" != configure ]; then
    exit 0
fi

if ! getent passwd nocert-sentinel >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin nocert-sentinel
fi

chown -R nocert-sentinel:nocert-sentinel /etc/nocert-sentinel

# Only touch systemd when it is the running init. Testing for the binary isn't
# enough: in containers/chroots systemctl can exist while systemd isn't PID 1,
# and calling it there aborts the install under `set -e`.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable nocert-sentinel
    # On upgrade, restart to pick up the new binary; no-op on first install
    # (the operator starts the service after enrollment).
    systemctl try-restart nocert-sentinel
else
    echo "Note: systemd not running, skipping systemd integration."
fi

# The enrollment identity lives in the key file. Its presence means this host
# has already enrolled, so re-showing the --enroll-token line would be wrong:
# that flag forces a fresh enrollment (new sentinel_id), orphaning the old one.
KEY_FILE=/etc/nocert-sentinel/sentinel-key.json

echo ""
if [ -f "$KEY_FILE" ]; then
    echo "nocert-sentinel upgraded. This host is already enrolled. Nothing to do."
else
    echo "nocert-sentinel installed. Enroll this host to register it and start the service:"
    echo "  sudo nocert-sentinel --enroll-token YOUR_TOKEN"
    echo ""
    echo "Self-hosted? Set server_url in /etc/nocert-sentinel/config.yaml first."
fi
echo ""
