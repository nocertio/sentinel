#!/bin/sh
set -eu
work=$(mktemp -d)
image="nocert-legacy-test:${CI_JOB_ID:-local-$$}"
cleanup() {
    if [ -s "$work/container.id" ]; then
        docker rm -f "$(cat "$work/container.id")" >/dev/null 2>&1 || true
    fi
    docker image rm "$image" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
CGO_ENABLED=0 go test -c -tags=integration ./internal/scanner -o "$work/scanner.test"
cp test/integration/legacy/Dockerfile "$work/Dockerfile"
docker build --tag "$image" "$work"
# Loopback fixtures share this one container, regardless of runner host networking.
docker run --rm --cidfile "$work/container.id" --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory 256m "$image"
