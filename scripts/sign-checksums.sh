#!/bin/sh
# Called only by an operator-controlled release build, never by pull-request CI.
set -eu
: "${GPG_FINGERPRINT:?set the full approved signing-key fingerprint}"
case "$GPG_FINGERPRINT" in
  *[!0-9A-Fa-f]*|"") echo "GPG_FINGERPRINT must contain only hex characters" >&2; exit 1;;
esac
[ ${#GPG_FINGERPRINT} -eq 40 ] || { echo "expected a full 40-character fingerprint" >&2; exit 1; }
exec gpg --batch --local-user "$GPG_FINGERPRINT" --armor --detach-sign --output "$2" "$1"
