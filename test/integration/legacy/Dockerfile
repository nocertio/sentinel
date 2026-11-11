# Test-only OpenSSL, isolated from every network when the fixture runs.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential perl curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl --fail --location --proto '=https' --tlsv1.2 https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz -o openssl.tar.gz \
    && echo 'ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16  openssl.tar.gz' | sha256sum -c - \
    && tar -xzf openssl.tar.gz \
    && cd openssl-1.0.2u \
    && ./config no-shared enable-ssl2 enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers --prefix=/opt/legacy \
    && make -j2 build_libs build_apps \
    && mkdir -p /opt/legacy/bin \
    && cp apps/openssl /opt/legacy/bin/openssl
FROM debian:bookworm-slim
COPY --from=build /opt/legacy/bin/openssl /opt/legacy/bin/openssl
COPY scanner.test /usr/local/bin/scanner.test
ENV OPENSSL_LEGACY=/opt/legacy/bin/openssl
ENV OPENSSL_CONF=/dev/null
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/scanner.test", "-test.run=^Test(ProtocolDiscovery|DiscoveryWithoutHTTPALPN|UpgradeRawFallback|UpgradeEnumeration|UpgradeCancellationAndBudgetRelease|LegacyIntegration|UnusualCertificates|CertificateChainLimits|CertificateRejectionDoesNotStopScan|GentleScanSkipsExtraProbes|ScanDialerSharesIPAcrossPortsAndHostname)$", "-test.v", "-test.timeout=3m"]
