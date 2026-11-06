#!/usr/bin/env python3
"""Package an already-built, static Linux/mipsle binary without user data."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import re
import struct
import tarfile


def archive(files):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, data, mode in files:
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.mtime = len(data), mode, 0
            member.uid = member.gid = 0
            tar.addfile(member, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def build_release(binary, version, output, repo=None):
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2,3}(?:[+~-][A-Za-z0-9.]+)?", version):
        raise ValueError("invalid release version")
    repo = Path(repo or Path(__file__).resolve().parent.parent)
    payload = Path(binary).read_bytes()
    if (len(payload) < 52 or payload[:6] != b"\x7fELF\x01\x01"
            or struct.unpack_from("<H", payload, 18)[0] != 8):
        raise ValueError("expected a 32-bit little-endian MIPS ELF binary")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    init = (repo / "packaging/opkg/esurfing-go-webui").read_bytes().replace(b"\r\n", b"\n")
    license_text = (repo / "LICENSE").read_bytes().replace(b"\r\n", b"\n")
    data = archive([
        ("usr/bin/esurfing-go-webui", payload, 0o755),
        ("etc/init.d/esurfing-go-webui", init, 0o755),
        ("usr/share/licenses/esurfing-go-webui/LICENSE", license_text, 0o644),
    ])
    control = (f"Package: esurfing-go-webui\nVersion: {version}\n"
               "Architecture: mipsel_24kc\nDepends: libc\nSection: net\n"
               "Maintainer: Esurfing-go-webui contributors\nLicense: Apache-2.0\n"
               # OpenWrt 23.05 ipkg-build uses the compressed data archive byte count.
               f"Installed-Size: {len(data)}\n"
               "Description: Campus authentication web UI, router optimization preview\n").encode()
    postinst = b'''#!/bin/sh
[ -z "$IPKG_INSTROOT" ] || exit 0
/etc/init.d/esurfing-go-webui enable
/etc/init.d/esurfing-go-webui restart
'''
    prerm = b'''#!/bin/sh
[ -z "$IPKG_INSTROOT" ] || exit 0
/etc/init.d/esurfing-go-webui stop
if [ "$1" = remove ]; then /etc/init.d/esurfing-go-webui disable; fi
'''
    metadata = archive([
        ("control", control, 0o644),
        ("conffiles", b"/etc/esurfing-webui/config.json\n", 0o644),
        ("postinst", postinst, 0o755),
        ("prerm", prerm, 0o755),
    ])
    executable = output / f"esurfing-go-webui-{version}-linux-mipsle"
    executable.write_bytes(payload)
    package = output / f"esurfing-go-webui_{version}_mipsel_24kc.ipk"
    package.write_bytes(archive([
        ("debian-binary", b"2.0\n", 0o644),
        ("control.tar.gz", metadata, 0o644),
        ("data.tar.gz", data, 0o644),
    ]))
    license_file = output / "LICENSE.txt"
    license_file.write_bytes(license_text)
    assets = [executable, package, license_file]
    checksums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in assets)
    (output / "SHA256SUMS.txt").write_text(checksums, encoding="utf-8", newline="\n")
    return assets


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    for asset in build_release(args.binary, args.version, args.output):
        print(f"{asset.name}: {asset.stat().st_size} bytes")
