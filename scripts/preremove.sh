#!/bin/sh
set -e

# Both package managers also run this script on upgrade: dpkg with "upgrade",
# rpm with the number of instances left (1). Only a real removal ("remove" or
# 0) stops and disables the service, so an upgrade keeps it running.
if [ "$1" = remove ] || [ "$1" = 0 ]; then
    systemctl stop nocert-sentinel 2>/dev/null || true
    systemctl disable nocert-sentinel 2>/dev/null || true
fi
