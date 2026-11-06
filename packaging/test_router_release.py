import hashlib
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

from build_router_release import build_release


class RouterPackageTests(unittest.TestCase):
    def test_package_architecture_permissions_checksums_and_no_user_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "input"
            elf = bytearray(64)
            elf[:6] = b"\x7fELF\x01\x01"
            struct.pack_into("<H", elf, 18, 8)
            binary.write_bytes(elf)
            first, second = root / "first", root / "second"
            assets = build_release(binary, "26.11.6.1", first)
            build_release(binary, "26.11.6.1", second)
            package = assets[1]
            self.assertEqual(package.read_bytes(), (second / package.name).read_bytes())
            with tarfile.open(package, "r:gz") as outer:
                self.assertEqual(set(outer.getnames()), {"debian-binary", "control.tar.gz", "data.tar.gz"})
                with tarfile.open(fileobj=io.BytesIO(outer.extractfile("control.tar.gz").read()), mode="r:gz") as control:
                    text = control.extractfile("control").read().decode()
                    self.assertIn("Version: 26.11.6.1\n", text)
                    self.assertIn("Architecture: mipsel_24kc\n", text)
                    installed_bytes = len(outer.extractfile("data.tar.gz").read())
                    self.assertIn(f"Installed-Size: {installed_bytes}\n", text)
                    self.assertEqual(control.getmember("postinst").mode, 0o755)
                with tarfile.open(fileobj=io.BytesIO(outer.extractfile("data.tar.gz").read()), mode="r:gz") as data:
                    self.assertEqual(data.getmember("usr/bin/esurfing-go-webui").mode, 0o755)
                    self.assertEqual(data.extractfile("usr/bin/esurfing-go-webui").read(), bytes(elf))
                    self.assertNotIn("etc/esurfing-webui/config.json", data.getnames())
                    self.assertFalse(any("sessions" in n or "/log/" in n for n in data.getnames()))
            for line in (first / "SHA256SUMS.txt").read_text().splitlines():
                checksum, name = line.split("  ")
                self.assertEqual(checksum, hashlib.sha256((first / name).read_bytes()).hexdigest())

    def test_rejects_wrong_architecture_and_unsafe_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "input"
            binary.write_bytes(b"not an ELF")
            with self.assertRaises(ValueError):
                build_release(binary, "26.11.6.1", root / "out")
            with self.assertRaises(ValueError):
                build_release(binary, "26.11.6.1\nInjected: yes", root / "out")


if __name__ == "__main__":
    unittest.main()
