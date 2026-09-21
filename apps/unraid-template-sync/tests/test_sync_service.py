from __future__ import annotations

import ipaddress
import json
import http.client
import hmac
import hashlib
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer


APP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_DIR))

from sync_service import (  # noqa: E402
    Config,
    TemplateSynchronizer,
    WebhookApplication,
    make_handler,
    parse_networks,
    resolve_client_address,
    signature_is_valid,
)


class SecurityTests(unittest.TestCase):
    def test_github_documented_signature_vector(self) -> None:
        secret = b"It's a Secret to Everybody"
        body = b"Hello, World!"
        signature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
        self.assertTrue(signature_is_valid(secret, body, signature))
        self.assertFalse(signature_is_valid(secret, body + b"!", signature))
        self.assertFalse(signature_is_valid(secret, body, None))

    def test_client_address_uses_rightmost_untrusted_hop(self) -> None:
        trusted = parse_networks("172.16.0.0/12")
        client = resolve_client_address(
            "172.17.0.2",
            "203.0.113.99, 140.82.115.4",
            trusted,
        )
        self.assertEqual(client, ipaddress.ip_address("140.82.115.4"))

    def test_direct_client_cannot_spoof_forwarded_for(self) -> None:
        trusted = parse_networks("172.16.0.0/12")
        client = resolve_client_address("192.0.2.50", "140.82.115.4", trusted)
        self.assertEqual(client, ipaddress.ip_address("192.0.2.50"))


class _StubNetworks:
    def contains(self, _address: object) -> bool:
        return True

    def snapshot(self) -> tuple[tuple[str, ...], str | None]:
        return (("192.0.2.0/24",), "now")


class _StubWorker:
    def __init__(self) -> None:
        self.reasons: list[str] = []

    def enqueue(self, reason: str) -> bool:
        self.reasons.append(reason)
        return True

    def snapshot(self) -> dict[str, object]:
        return {"state": "ok"}


class WebhookTests(unittest.TestCase):
    def test_valid_push_is_queued_and_invalid_signature_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = Config(
                webhook_secret=b"secret",
                github_repository="Lowess/docker-templates-unraid",
                github_branch="main",
                git_remote_url="https://example.invalid/repository.git",
                git_remote_tracking_name="origin",
                repo_dir=root / "repository",
                source_dir=root / "repository" / "Lowess",
                destination_dir=root / "destination",
                state_dir=root / "state",
                listen_address="127.0.0.1",
                port=9000,
                max_body_bytes=1_048_576,
                sync_timeout_seconds=30,
                sync_on_start=True,
                git_clean=True,
                enforce_github_ips=False,
                trusted_proxy_networks=(),
                github_meta_refresh_seconds=21_600,
            )
            worker = _StubWorker()
            application = WebhookApplication(config, _StubNetworks(), worker)  # type: ignore[arg-type]
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(application))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                body = json.dumps(
                    {
                        "repository": {"full_name": "Lowess/docker-templates-unraid"},
                        "ref": "refs/heads/main",
                        "deleted": False,
                    }
                ).encode()
                signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
                headers = {
                    "Content-Type": "application/json",
                    "X-GitHub-Event": "push",
                    "X-GitHub-Delivery": "delivery-1",
                    "X-Hub-Signature-256": signature,
                }
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
                connection.request("POST", "/webhook", body=body, headers=headers)
                response = connection.getresponse()
                self.assertEqual(response.status, 202)
                self.assertEqual(json.loads(response.read())["status"], "sync queued")
                self.assertEqual(worker.reasons, ["GitHub delivery delivery-1"])
                connection.close()

                headers["X-GitHub-Delivery"] = "delivery-2"
                headers["X-Hub-Signature-256"] = "sha256=" + "0" * 64
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
                connection.request("POST", "/webhook", body=body, headers=headers)
                response = connection.getresponse()
                self.assertEqual(response.status, 401)
                response.read()
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


class SynchronizerTests(unittest.TestCase):
    def git(self, directory: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(directory), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def test_sync_resets_checkout_and_mirrors_only_xml(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            remote = root / "remote.git"
            author = root / "author"
            checkout = root / "checkout"
            destination = root / "destination"

            subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
            subprocess.run(["git", "clone", str(remote), str(author)], check=True, capture_output=True)
            self.git(author, "config", "user.email", "test@example.com")
            self.git(author, "config", "user.name", "Test")
            self.git(author, "switch", "-c", "main")
            (author / "Lowess").mkdir()
            (author / "Lowess" / "one.xml").write_text("<one/>\n", encoding="utf-8")
            (author / "Lowess" / "ignored.txt").write_text("ignored\n", encoding="utf-8")
            self.git(author, "add", ".")
            self.git(author, "commit", "-m", "initial")
            self.git(author, "push", "-u", "origin", "main")
            subprocess.run(["git", "clone", "--branch", "main", str(remote), str(checkout)], check=True, capture_output=True)

            (checkout / "untracked.txt").write_text("remove me\n", encoding="utf-8")
            destination.mkdir()
            (destination / "stale.xml").write_text("<stale/>\n", encoding="utf-8")
            (destination / "keep.txt").write_text("keep\n", encoding="utf-8")

            config = Config(
                webhook_secret=b"secret",
                github_repository="Lowess/docker-templates-unraid",
                github_branch="main",
                git_remote_url=str(remote),
                git_remote_tracking_name="origin",
                repo_dir=checkout,
                source_dir=checkout / "Lowess",
                destination_dir=destination,
                state_dir=root / "state",
                listen_address="127.0.0.1",
                port=9000,
                max_body_bytes=1_048_576,
                sync_timeout_seconds=30,
                sync_on_start=True,
                git_clean=True,
                enforce_github_ips=False,
                trusted_proxy_networks=(),
                github_meta_refresh_seconds=21_600,
            )
            commit = TemplateSynchronizer(config).sync()

            self.assertEqual(commit, self.git(checkout, "rev-parse", "--short", "HEAD"))
            self.assertEqual((destination / "one.xml").read_text(), "<one/>\n")
            self.assertFalse((destination / "stale.xml").exists())
            self.assertEqual((destination / "keep.txt").read_text(), "keep\n")
            self.assertFalse((checkout / "untracked.txt").exists())
            self.assertFalse((destination / "ignored.txt").exists())


if __name__ == "__main__":
    unittest.main()
