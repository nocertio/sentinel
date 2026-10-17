#!/bin/sh
set -e

# dpkg also runs prerm on upgrade (with "$1" = upgrade); only stop/disable on a
# real remove, so an `apt upgrade` doesn't tear down the running service.
if [ "$1" = remove ]; then
    systemctl stop nocert-sentinel 2>/dev/null || true
    systemctl disable nocert-sentinel 2>/dev/null || true
fi
