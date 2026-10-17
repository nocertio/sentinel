# Source-build image for network and Kubernetes collection only.
FROM golang:1.27.2-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY cmd/ cmd/
COPY internal/ internal/
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -mod=vendor -trimpath -buildvcs=false \
    -ldflags "-s -w -X nocert.io/sentinel/internal/version.Version=${VERSION}" \
    -o /out/nocert-sentinel ./cmd/nocert-sentinel

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/nocert-sentinel && chown 65532:65532 /etc/nocert-sentinel
COPY --from=build /out/nocert-sentinel /usr/local/bin/nocert-sentinel
COPY LICENSE THIRD_PARTY_NOTICES /usr/share/doc/nocert-sentinel/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/nocert-sentinel"]
CMD ["--config", "/etc/nocert-sentinel/config.yaml"]
