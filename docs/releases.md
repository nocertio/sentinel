# Build and verify a release

The source includes a GoReleaser configuration for Linux amd64/arm64 binaries,
tar archives, Debian packages, a source archive, SPDX SBOMs and SHA-256 sums.
Use Go 1.27.2, GoReleaser 2.15.4, Syft 1.54.1 and Python 3. This configuration does not
publish to any repository, registry or release service.

For an unsigned local candidate:

```sh
goreleaser release --snapshot --clean --skip=publish,sign
python3 scripts/release-assets.py
```

The manual GitHub workflow builds that same unsigned candidate without signing
keys. An operator reviews and promotes a release separately. Pull requests
cannot trigger a signing or publishing job.

For an approved tag, an operator with the signing key available runs:

```sh
export GPG_FINGERPRINT=D5EFCB2E291B386D51618CB3E1DFFDD9DF7BBB21
goreleaser release --clean --skip=publish,sign
python3 scripts/release-assets.py
# Review the assembled assets before signing.
sh scripts/sign-checksums.sh release/checksums.txt release/checksums.txt.asc
```

Only files in `release/` are intended for distribution. The assembly step removes
builder ownership, timestamps and Git archive comments from tar headers, excludes
GoReleaser diagnostics, and computes checksums over the final bytes. It requires
a new output directory so an older signature cannot survive a rebuild. Keep
`dist/metadata.json`, `dist/artifacts.json` and `dist/config.yaml` local.

The final command signs `checksums.txt`, which covers the packages, binary archives, source
archive and SBOMs. The existing APT repository and source archive distribution
retain their own signature files. Import the public key from
`https://repo.nocert.io/apt/gpg.key`, check its fingerprint independently against
the NoCert source page, then verify a downloaded release in a fresh directory:

```sh
gpg --verify checksums.txt.asc checksums.txt
sha256sum -c checksums.txt
```

Do not treat a test key or unsigned workflow artifact as an official release.
For reproducibility, compare the unpacked agent binaries with a rebuild using
the exact release version, compiler and flags in the README. Package archive
metadata, SBOM timestamps and container layers are outside that claim.
