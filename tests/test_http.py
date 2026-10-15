"""Exercise the real Uvicorn HTTP entry point and on-disk restart persistence."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


class HTTPTests(unittest.TestCase):
    def test_process_restart_preserves_history(self):
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            base = f'http://127.0.0.1:{port}'
            env = {**os.environ, 'PORT': str(port), 'CBOR_DATA_DIR': directory}

            def start():
                process = subprocess.Popen([sys.executable, 'app.py'], cwd=ROOT, env=env,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for _ in range(100):
                    if process.poll() is not None:
                        self.fail('HTTP server exited before becoming ready')
                    try:
                        with urlopen(base + '/api/health', timeout=1) as response:
                            self.assertEqual(json.load(response)['status'], 'ok')
                            return process
                    except OSError:
                        time.sleep(.05)
                process.terminate()
                process.wait(timeout=5)
                self.fail('HTTP server did not become ready')

            def stop(process):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

            process = start()
            try:
                with urlopen(base, timeout=5) as response:
                    self.assertIn(b'CBOR Workbench', response.read())
                    self.assertIn("script-src 'self'", response.headers['Content-Security-Policy'])
                request = Request(base + '/api/analyze',
                                  data=json.dumps({'text': 'ff820102', 'format': 'hex'}).encode(),
                                  headers={'Content-Type': 'application/json'})
                with urlopen(request, timeout=5) as response:
                    self.assertEqual(response.status, 201)
                    saved = json.load(response)
                    self.assertEqual(saved['result']['selected']['offset'], 1)
            finally:
                stop(process)
            process = start()
            try:
                with urlopen(base + '/api/history', timeout=5) as response:
                    rows = json.load(response)
                    self.assertEqual([row['id'] for row in rows], [saved['id']])
                with urlopen(base + '/api/history/' + saved['id'] + '/export?format=cbor', timeout=5) as response:
                    self.assertEqual(response.read(), bytes.fromhex('ff820102'))
            finally:
                stop(process)


if __name__ == '__main__':
    unittest.main()
