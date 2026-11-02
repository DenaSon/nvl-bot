"""Local-only, deterministic DenaProbe relay responder smoke test."""
import socket
import subprocess
import sys
import time
from pathlib import Path
import unittest


class TestResponder(unittest.TestCase):
    def test_bounded_loopback_payload(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        script = (Path(__file__).resolve().parents[1] /
                  "ops/denaprobe_static_responder.py")
        p = subprocess.Popen([sys.executable, str(script), "--port", str(port),
                              "--bytes", "4096"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        try:
            body = None
            for _ in range(35):
                if p.poll() is not None:
                    self.fail("responder crashed at startup")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.3) as sock:
                        content = bytearray()
                        while True:
                            chunk = sock.recv(2048)
                            if not chunk:
                                break
                            content.extend(chunk)
                        body = bytes(content)
                    break
                except (ConnectionRefusedError, TimeoutError):
                    time.sleep(0.05)
            self.assertEqual(body, b"Z" * 4096)
        finally:
            p.terminate()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
