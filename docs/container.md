# Container build

This is a Linux source-build option for network and Kubernetes scans. Container
filesystem and listener visibility differ from the host. It is not a substitute
for the Debian service when you need host filesystem or local-listener discovery.
No registry image or Helm deployment is currently supported.

```sh
docker build --provenance=false --build-arg VERSION=dev -t nocert-sentinel:local .
docker run --rm nocert-sentinel:local --version
```

Prepare a dedicated writable state directory owned by UID/GID 65532, mode 0700.
Put a `config.yaml` in it, owned by the same user, mode 0600:

```yaml
server_url: "https://sentinel.nocert.io"
key_file: /etc/nocert-sentinel/sentinel-key.json
allow_network_scan: true
allow_filesystem_scan: false
allow_local_scan: false
allow_kubernetes_scan: false
```

Supply the enrollment token in a protected env file; do not bake it into the
image or copy an enrolled signing key between instances. Start one instance
per state directory, substituting absolute local paths:

```sh
docker run -d --name nocert-sentinel \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount type=bind,src=/absolute/sentinel-state,dst=/etc/nocert-sentinel \
  --env-file /absolute/protected-enrollment.env \
  nocert-sentinel:local
```

Allow outbound access to the backend and authorized scan targets. For Kubernetes,
mount only the required CA/token files read-only, configure them as described in
the Kubernetes guide and enable that scan type. Do not mount the Docker socket,
the host root filesystem or use privileged mode.

The container image includes OS packages and is not claimed to be reproducible.
Pin base-image digests and review their updates before operating a registry
distribution. The binary has the same reproducible build flags as native builds.
Build only from the published source tree. Review any provenance attestation
before enabling it: attestations can expose build arguments and repository
metadata. Never pass credentials through build arguments.
