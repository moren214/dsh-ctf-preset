import bz2
import json
import lzma
import os
import struct
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORKERS_DIR = os.path.join(ROOT, "core", "workers")


def run_worker(script_name, args, stdin_bytes=b""):
    path = os.path.join(WORKERS_DIR, script_name)
    return subprocess.run(
        [sys.executable, path, *args],
        input=stdin_bytes,
        capture_output=True,
        timeout=15,
    )


def build_gguf(kvs):
    parts = [b"GGUF", struct.pack("<IQQ", 3, 0, len(kvs))]
    for k, v in kvs:
        kb = k.encode("utf-8")
        vb = v.encode("utf-8")
        parts.append(struct.pack("<Q", len(kb)) + kb)
        parts.append(struct.pack("<I", 8))
        parts.append(struct.pack("<Q", len(vb)) + vb)
    return b"".join(parts)


class WorkerSuiteTest(unittest.TestCase):
    def test_media_reader_gguf_safetensors_pickle(self):
        arg = json.dumps({"kind": "model"})
        gguf = build_gguf([("tokenizer.chat_template", '{{ "".\\x5f\\x5fclass\\x5f\\x5f.mro() }}')])
        p1 = run_worker("media-reader-worker.py", [arg], gguf)
        self.assertEqual(p1.returncode, 0, p1.stderr)
        r1 = json.loads(p1.stdout.decode("utf-8"))
        self.assertEqual(r1["risk_level"], "high")

        large_gguf = build_gguf([("general.description", "A" * (70 * 1024))])
        p2 = run_worker("media-reader-worker.py", [arg], large_gguf)
        self.assertEqual(p2.returncode, 0, p2.stderr)
        r2 = json.loads(p2.stdout.decode("utf-8"))
        self.assertTrue(r2["metadata_truncated"])

        header = json.dumps({"__metadata__": {"prompt": "{{ lipsum.__globals__ }}"}}).encode("utf-8")
        st_bytes = struct.pack("<Q", len(header)) + header
        p3 = run_worker("media-reader-worker.py", [arg], st_bytes)
        self.assertEqual(p3.returncode, 0, p3.stderr)
        self.assertEqual(json.loads(p3.stdout.decode("utf-8"))["risk_level"], "high")

        proto0 = b'cos\nsystem\n)\x81}S"k"\nS"v"\nsb'
        p4 = run_worker("media-reader-worker.py", [arg], proto0)
        self.assertEqual(p4.returncode, 0, p4.stderr)
        r4 = json.loads(p4.stdout.decode("utf-8"))
        self.assertEqual(r4["format"], "pickle")
        self.assertEqual(r4["risk_level"], "high")

    def test_compressed_stream_worker(self):
        payload = b"CTF_DECOMPRESS_OK"
        p_bz = run_worker("compressed-stream-worker.py", ["bzip2"], bz2.compress(payload))
        self.assertEqual(p_bz.returncode, 0, p_bz.stderr)
        self.assertEqual(p_bz.stdout, payload)

        p_xz = run_worker("compressed-stream-worker.py", ["xz"], lzma.compress(payload))
        self.assertEqual(p_xz.returncode, 0, p_xz.stderr)
        self.assertEqual(p_xz.stdout, payload)

        bad = run_worker("compressed-stream-worker.py", ["xz"], b"not-xz")
        self.assertEqual(bad.returncode, 3)

    def test_archive_directory_worker_7z_guard(self):
        p = run_worker("archive-directory-worker.py", ["7z", "0", "4", ""], b"not a 7z archive")
        self.assertEqual(p.returncode, 0, p.stderr)
        res = json.loads(p.stdout.decode("utf-8"))
        self.assertEqual(res["status"], "invalid")

    def test_flask_route_worker(self):
        src = (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.route('/admin')\n"
            "def admin():\n"
            "    return 'ok', 200\n"
        )
        req = json.dumps({
            "files": [{"file_path": "app.py", "module": "app", "source": src}],
            "entrypoint": "app",
            "request": {"method": "GET", "path": "/admin"},
        }).encode("utf-8")
        p = run_worker("flask-route-worker.py", [], req)
        self.assertEqual(p.returncode, 0, p.stderr)
        res = json.loads(p.stdout.decode("utf-8"))
        self.assertEqual(res["status"], "matched")
        self.assertEqual(res["match_count"], 1)

    def test_rev_disasm_worker_compile(self):
        p = subprocess.run(
            [sys.executable, "-m", "py_compile", os.path.join(WORKERS_DIR, "rev-disasm-worker.py")],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_workbench_base100_worker_protocol(self):
        p = run_worker("workbench-base100-worker.py", [], b"")
        self.assertIn(p.returncode, (0, 1))


if __name__ == "__main__":
    unittest.main()
