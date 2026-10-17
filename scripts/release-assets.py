#!/usr/bin/env python3
"""Assemble unsigned release assets; discard build diagnostics and tar metadata."""
import argparse
import copy
import gzip
import hashlib
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile

ASSET = re.compile(r"^nocert-sentinel[-_][A-Za-z0-9._~+-]+(?:\.deb|\.tar\.gz|\.sbom\.json)$")


def normalize_tar(source, destination):
    with tarfile.open(source, "r:gz") as old, destination.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.USTAR_FORMAT) as new:
                seen = set()
                for entry in old:
                    path = PurePosixPath(entry.name)
                    if (path.is_absolute() or ".." in path.parts or "\\" in entry.name
                            or any(ord(c) < 32 or ord(c) == 127 for c in entry.name)
                            or entry.name in seen or not (entry.isfile() or entry.isdir())):
                        raise ValueError("unsafe archive member")
                    seen.add(entry.name)
                    clean = copy.copy(entry)
                    clean.uid = clean.gid = clean.mtime = 0
                    clean.uname = clean.gname = "root"
                    clean.pax_headers = {}
                    new.addfile(clean, old.extractfile(entry) if entry.isfile() else None)
                if not seen:
                    raise ValueError("empty archive")


def assemble(source, output):
    if output.exists() or output.is_symlink():
        raise ValueError("output must be a new directory")
    assets = sorted(p for p in source.iterdir() if ASSET.fullmatch(p.name))
    if not assets or any(p.is_symlink() or not p.is_file() for p in assets):
        raise ValueError("missing or unsafe release assets")
    sources = [re.fullmatch(r"nocert-sentinel-(.+)-source\.tar\.gz", p.name) for p in assets]
    sources = [match for match in sources if match]
    if len(sources) != 1:
        raise ValueError("exactly one source archive is required")
    version = sources[0][1]
    expected = {f"nocert-sentinel-{version}-source.tar.gz"}
    expected.update(f"nocert-sentinel_{version}_linux_{arch}.{suffix}"
                    for arch in ("amd64", "arm64") for suffix in ("deb", "tar.gz", "sbom.json"))
    if {p.name for p in assets} != expected:
        raise ValueError("release must contain the complete two-architecture asset set for one version")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent, prefix="release-assets-") as temp:
        prepared = Path(temp) / "assets"
        prepared.mkdir()
        hashes = []
        for asset in assets:
            dest = prepared / asset.name
            if asset.name.endswith(".tar.gz"):
                normalize_tar(asset, dest)
            else:
                shutil.copyfile(asset, dest)
            dest.chmod(0o644)
            hashes.append(f"{hashlib.sha256(dest.read_bytes()).hexdigest()}  {dest.name}\n")
        (prepared / "checksums.txt").write_text("".join(hashes))
        prepared.rename(output)
    print(f"Prepared {len(assets)} unsigned assets in {output}; sign these checksums after review")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, default=Path("release"))
    args = parser.parse_args()
    assemble(args.dist, args.output)
