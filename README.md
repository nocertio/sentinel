# NoCert Sentinel

Sentinel collects TLS certificates from private networks, Linux hosts and
Kubernetes clusters for [NoCert](https://nocert.io). It records where each
certificate is deployed so you can track it alongside your public-facing services.

It collects certificates from:

- **Network endpoints:** TLS connections to the IP ranges and ports you configure.
- **Linux hosts:** local listeners and certificate files the service can read.
- **Kubernetes:** certificate fields in supported Secrets and ConfigMaps.

Sentinel requires a NoCert account. Scan jobs come from NoCert; there is no
standalone scan command. It does not issue or renew certificates.

## Install

Packages are available for **Debian and Ubuntu, amd64 and arm64**, with systemd.

Add the repository signing key:

```sh
sudo apt update
sudo apt install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://repo.nocert.io/apt/gpg.key -o /etc/apt/keyrings/nocert.asc
sudo chmod a+r /etc/apt/keyrings/nocert.asc
gpg --show-keys --fingerprint /etc/apt/keyrings/nocert.asc
```

The fingerprint is `D5EF CB2E 291B 386D 5161 8CB3 E1DF FDD9 DF7B BB21`.
You can also check it on the [source distribution page](https://nocert.io/sentinel-source).

Add the APT source and install:

```sh
sudo tee /etc/apt/sources.list.d/nocert.sources >/dev/null <<'EOF'
Types: deb
URIs: https://repo.nocert.io/apt
Suites: stable
Components: main
Architectures: amd64 arm64
Signed-By: /etc/apt/keyrings/nocert.asc
EOF
sudo apt update
sudo apt install nocert-sentinel
```

In NoCert, open **Sentinels > Deploy Sentinel** to get an enrollment token.
Create `/etc/nocert-sentinel/enroll.env` as root with mode `0600`, containing:

```text
NOCERT_ENROLL_TOKEN=your-enrollment-token
```

Then start the service:

```sh
sudo systemctl start nocert-sentinel
sudo journalctl -u nocert-sentinel -f
```

The host will appear in your Sentinel inventory. See the
[enrollment guide](https://docs.nocert.io/sentinels/enrollment) for fleet deployment
and token handling. Avoid passing the token on the command line, where it can
appear in process arguments.

## Configure collection

Configuration lives in `/etc/nocert-sentinel/config.yaml`. Each scan type can be
disabled locally, even if NoCert requests it:

```yaml
server_url: "https://sentinel.nocert.io"
allow_network_scan: true
allow_filesystem_scan: true
allow_local_scan: true
allow_kubernetes_scan: false
log_level: info
```

Restart the service after changing the file. Unknown configuration keys cause
startup to fail. The [example configuration](configs/config.example.yaml) and
[configuration reference](https://docs.nocert.io/sentinels/configuration) cover
the remaining settings.

For Kubernetes, follow the [setup guide](https://docs.nocert.io/sentinels/kubernetes)
and [example RBAC](configs/kubernetes-rbac.yaml). Sentinel can connect from a Linux
host outside the cluster. Grant access only to the namespaces you intend to scan.

If your host uses an outbound proxy, configure it in the service environment
with `sudo systemctl edit nocert-sentinel`:

```ini
[Service]
Environment="HTTPS_PROXY=http://proxy.example.com:3128"
Environment="NO_PROXY=localhost,127.0.0.1"
```

Restart the service to apply it. A proxy that intercepts HTTPS needs its CA in
the host trust store. Proxy settings apply to the connection to NoCert; TLS
probes connect directly to scan targets. APT has its own proxy configuration.

## Data and permissions

Sentinel sends certificate bytes and deployment locations to NoCert. Depending
on the source, locations include IP addresses, file paths, namespaces and object
names. These observations can contain internal hostnames and application names.

Private keys and Kubernetes credentials are not uploaded. Reading a Kubernetes
Secret does expose the complete object to the local agent; Kubernetes RBAC
cannot grant access to just its certificate fields. See
[data collection and security](docs/data-collection.md) for the fields reported
and how connections are authenticated.

The Debian service runs as an unprivileged user with systemd restrictions. It
needs outbound access to NoCert and the scan targets, with no inbound listener.
Filesystem discovery is limited to files that this service user can read.

## Build from source

Use Go **1.27.2**. Dependencies are included in `vendor/`; building this checkout
does not require access to another repository.

```sh
GOTOOLCHAIN=go1.27.2 go test -mod=vendor -race ./...
GOTOOLCHAIN=go1.27.2 go vet -mod=vendor ./...
GOTOOLCHAIN=go1.27.2 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -mod=vendor -trimpath -buildvcs=false \
  -ldflags '-s -w -X nocert.io/sentinel/internal/version.Version=VERSION' \
  -o nocert-sentinel ./cmd/nocert-sentinel
```

Replace `VERSION` with the release version; use `GOARCH=arm64` for ARM64.
To reproduce a distributed binary, start from that release's signed source
archive and use the same compiler and flags. See [release verification](docs/releases.md).
GitHub workflow artifacts are unsigned build candidates, not official releases.

The [Dockerfile](Dockerfile) supports source builds for network and Kubernetes
collection. Follow the [container instructions](docs/container.md) for its scope
and required mounts. No prebuilt image or Helm chart is published. Windows and
macOS are not supported.

## Contributing

Bug reports and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md)
for the development workflow and [SECURITY.md](SECURITY.md) to report a vulnerability
privately. Keep credentials and customer inventories out of issues.

Sentinel is licensed under [Apache-2.0](LICENSE). The vendored shared library
uses MIT; dependency notices are in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
