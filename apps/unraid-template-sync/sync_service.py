#!/usr/bin/env python3
"""Receive authenticated GitHub webhooks and refresh Unraid CA templates."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable


LOG = logging.getLogger("unraid-template-sync")
GITHUB_META_URL = "https://api.github.com/meta"
GITHUB_API_VERSION = "2026-03-10"
REF_FORBIDDEN = re.compile(r"(?:\.\.|@\{|[\\\s~^:?*\[])")


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


def env_int(name: str, default: int, minimum: int = 1) -> int:
    value = int(os.getenv(name, str(default)))
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def validate_ref_component(value: str, name: str) -> str:
    if (
        not value
        or value.startswith(('-', '.', '/'))
        or value.endswith(('.', '/'))
        or '//' in value
        or REF_FORBIDDEN.search(value)
        or any(part.endswith('.lock') for part in value.split('/'))
    ):
        raise ValueError(f"{name} is not a safe Git ref component")
    return value


def parse_networks(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for item in value.split(','):
        item = item.strip()
        if item:
            networks.append(ipaddress.ip_network(item, strict=False))
    return tuple(networks)


@dataclass(frozen=True)
class Config:
    webhook_secret: bytes
    github_repository: str
    github_branch: str
    git_remote_url: str
    git_remote_tracking_name: str
    repo_dir: Path
    source_dir: Path
    destination_dir: Path
    state_dir: Path
    listen_address: str
    port: int
    max_body_bytes: int
    sync_timeout_seconds: int
    sync_on_start: bool
    git_clean: bool
    enforce_github_ips: bool
    trusted_proxy_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    github_meta_refresh_seconds: int

    @classmethod
    def from_environment(cls) -> "Config":
        secret = os.getenv("WEBHOOK_SECRET", "")
        if not secret:
            raise ValueError("WEBHOOK_SECRET is required")

        repository = os.getenv("GITHUB_REPOSITORY", "Lowess/docker-templates-unraid").strip()
        if repository.count("/") != 1 or any(not part for part in repository.split("/")):
            raise ValueError("GITHUB_REPOSITORY must use the owner/repository form")

        branch = validate_ref_component(os.getenv("GITHUB_BRANCH", "main").strip(), "GITHUB_BRANCH")
        tracking_name = validate_ref_component(
            os.getenv("GIT_REMOTE_TRACKING_NAME", "origin").strip(),
            "GIT_REMOTE_TRACKING_NAME",
        )
        repo_dir = Path(os.getenv("REPO_DIR", "/repo")).resolve()
        source_subdir = Path(os.getenv("SOURCE_SUBDIR", "Lowess"))
        if source_subdir.is_absolute() or ".." in source_subdir.parts:
            raise ValueError("SOURCE_SUBDIR must be a relative path without '..'")
        source_dir = (repo_dir / source_subdir).resolve()
        if not source_dir.is_relative_to(repo_dir):
            raise ValueError("SOURCE_SUBDIR must resolve inside REPO_DIR")
        git_remote_url = os.getenv(
            "GIT_REMOTE_URL",
            "https://github.com/Lowess/docker-templates-unraid.git",
        ).strip()
        if not git_remote_url:
            raise ValueError("GIT_REMOTE_URL is required")

        return cls(
            webhook_secret=secret.encode("utf-8"),
            github_repository=repository,
            github_branch=branch,
            git_remote_url=git_remote_url,
            git_remote_tracking_name=tracking_name,
            repo_dir=repo_dir,
            source_dir=source_dir,
            destination_dir=Path(os.getenv("DEST_DIR", "/templates")).resolve(),
            state_dir=Path(os.getenv("STATE_DIR", "/data")).resolve(),
            listen_address=os.getenv("LISTEN_ADDRESS", "0.0.0.0"),
            port=env_int("PORT", 9000),
            max_body_bytes=env_int("MAX_BODY_BYTES", 1_048_576),
            sync_timeout_seconds=env_int("SYNC_TIMEOUT_SECONDS", 120),
            sync_on_start=env_bool("SYNC_ON_START", True),
            git_clean=env_bool("GIT_CLEAN", True),
            enforce_github_ips=env_bool("ENFORCE_GITHUB_IPS", True),
            trusted_proxy_networks=parse_networks(
                os.getenv("TRUSTED_PROXY_CIDRS", "172.16.0.0/12")
            ),
            github_meta_refresh_seconds=env_int("GITHUB_META_REFRESH_SECONDS", 21_600, 300),
        )


def signature_is_valid(secret: bytes, body: bytes, supplied_signature: str | None) -> bool:
    if not supplied_signature or not supplied_signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, supplied_signature)


def address_in_networks(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def resolve_client_address(
    peer_address: str,
    forwarded_for: str | None,
    trusted_proxy_networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Walk an X-Forwarded-For chain right-to-left, trusting only known proxies."""
    peer = ipaddress.ip_address(peer_address)
    trusted = tuple(trusted_proxy_networks)
    if not forwarded_for or not address_in_networks(peer, trusted):
        return peer

    chain = []
    for item in forwarded_for.split(','):
        chain.append(ipaddress.ip_address(item.strip()))
    chain.append(peer)

    for address in reversed(chain):
        if not address_in_networks(address, trusted):
            return address
    raise ValueError("forwarded address chain contains only trusted proxies")


class GithubHookNetworks:
    def __init__(self, cache_path: Path, refresh_seconds: int, meta_url: str = GITHUB_META_URL):
        self.cache_path = cache_path
        self.refresh_seconds = refresh_seconds
        self.meta_url = meta_url
        self._lock = threading.Lock()
        self._networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
        self._refreshed_at: str | None = None
        self._stop = threading.Event()

    def load_cache(self) -> None:
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
            networks = tuple(ipaddress.ip_network(item) for item in payload["hooks"])
            if not networks:
                raise ValueError("cached hooks list is empty")
            with self._lock:
                self._networks = networks
                self._refreshed_at = payload.get("refreshed_at")
            LOG.info("Loaded %d GitHub hook networks from cache", len(networks))
        except FileNotFoundError:
            return
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            LOG.warning("Could not load GitHub hook network cache: %s", error)

    def refresh(self) -> None:
        request = urllib.request.Request(
            self.meta_url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "unraid-template-sync/1.0",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.load(response)
        networks = tuple(ipaddress.ip_network(item) for item in payload.get("hooks", []))
        if not networks:
            raise ValueError("GitHub Meta API returned no hook networks")

        refreshed_at = datetime.now(timezone.utc).isoformat()
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_payload = json.dumps(
            {"hooks": [str(network) for network in networks], "refreshed_at": refreshed_at},
            indent=2,
        ) + "\n"
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.cache_path.parent,
            prefix=".github-hooks-",
            delete=False,
        ) as temporary:
            temporary.write(cache_payload)
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, self.cache_path)

        with self._lock:
            self._networks = networks
            self._refreshed_at = refreshed_at
        LOG.info("Refreshed %d GitHub hook networks", len(networks))

    def refresh_forever(self) -> None:
        while not self._stop.wait(self.refresh_seconds):
            try:
                self.refresh()
            except Exception as error:  # Keep the last known-good set.
                LOG.error("Could not refresh GitHub hook networks: %s", error)

    def stop(self) -> None:
        self._stop.set()

    def contains(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        with self._lock:
            networks = self._networks
        return address_in_networks(address, networks)

    def snapshot(self) -> tuple[tuple[str, ...], str | None]:
        with self._lock:
            return tuple(str(network) for network in self._networks), self._refreshed_at


class TemplateSynchronizer:
    def __init__(self, config: Config):
        self.config = config

    def _git(self, *arguments: str) -> str:
        command = [
            "git",
            "-c",
            f"safe.directory={self.config.repo_dir}",
            "-C",
            str(self.config.repo_dir),
            *arguments,
        ]
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            text=True,
            timeout=self.config.sync_timeout_seconds,
        )
        return completed.stdout.strip()

    def sync(self) -> str:
        if not (self.config.repo_dir / ".git").is_dir():
            raise RuntimeError(f"{self.config.repo_dir} is not a Git working tree")
        if not self.config.source_dir.is_dir():
            raise RuntimeError(f"template source directory does not exist: {self.config.source_dir}")

        remote_ref = (
            f"refs/remotes/{self.config.git_remote_tracking_name}/{self.config.github_branch}"
        )
        fetch_refspec = f"+refs/heads/{self.config.github_branch}:{remote_ref}"
        self._git("fetch", "--prune", self.config.git_remote_url, fetch_refspec)
        self._git("reset", "--hard", remote_ref)
        if self.config.git_clean:
            self._git("clean", "-fd")

        self._sync_xml_files()
        return self._git("rev-parse", "--short", "HEAD")

    def _sync_xml_files(self) -> None:
        self.config.destination_dir.mkdir(parents=True, exist_ok=True)
        source_files = {
            item.name: item
            for item in self.config.source_dir.iterdir()
            if item.is_file() and not item.is_symlink() and item.suffix.lower() == ".xml"
        }

        for name, source in source_files.items():
            destination = self.config.destination_dir / name
            with tempfile.NamedTemporaryFile(
                "wb",
                dir=self.config.destination_dir,
                prefix=f".{name}.",
                delete=False,
            ) as temporary:
                with source.open("rb") as source_handle:
                    shutil.copyfileobj(source_handle, temporary)
                temporary_path = Path(temporary.name)
            os.replace(temporary_path, destination)

        for item in self.config.destination_dir.iterdir():
            if item.name not in source_files and item.suffix.lower() == ".xml":
                if item.is_file() or item.is_symlink():
                    item.unlink()


class SyncWorker:
    def __init__(self, synchronizer: TemplateSynchronizer):
        self.synchronizer = synchronizer
        self._requests: queue.Queue[str] = queue.Queue(maxsize=1)
        self._lock = threading.Lock()
        self._status: dict[str, Any] = {
            "state": "waiting",
            "last_reason": None,
            "last_commit": None,
            "last_completed_at": None,
            "last_error": None,
        }

    def start(self) -> None:
        threading.Thread(target=self._run, name="sync-worker", daemon=True).start()

    def enqueue(self, reason: str) -> bool:
        try:
            self._requests.put_nowait(reason)
            return True
        except queue.Full:
            return False

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._status)

    def _run(self) -> None:
        while True:
            reason = self._requests.get()
            with self._lock:
                self._status.update(state="syncing", last_reason=reason, last_error=None)
            try:
                LOG.info("Starting template sync (%s)", reason)
                commit = self.synchronizer.sync()
                with self._lock:
                    self._status.update(
                        state="ok",
                        last_commit=commit,
                        last_completed_at=datetime.now(timezone.utc).isoformat(),
                        last_error=None,
                    )
                LOG.info("Template sync completed at commit %s", commit)
            except Exception as error:
                LOG.exception("Template sync failed")
                with self._lock:
                    self._status.update(
                        state="error",
                        last_completed_at=datetime.now(timezone.utc).isoformat(),
                        last_error=str(error),
                    )
            finally:
                self._requests.task_done()


class WebhookApplication:
    def __init__(self, config: Config, networks: GithubHookNetworks, worker: SyncWorker):
        self.config = config
        self.networks = networks
        self.worker = worker
        self._deliveries: dict[str, float] = {}
        self._delivery_lock = threading.Lock()

    def client_is_allowed(self, peer: str, forwarded_for: str | None) -> bool:
        if not self.config.enforce_github_ips:
            return True
        client = resolve_client_address(peer, forwarded_for, self.config.trusted_proxy_networks)
        return self.networks.contains(client)

    def remember_delivery(self, delivery_id: str) -> bool:
        """Return False for a recently handled delivery; keep memory bounded."""
        now = time.monotonic()
        with self._delivery_lock:
            cutoff = now - 86_400
            self._deliveries = {
                key: timestamp for key, timestamp in self._deliveries.items() if timestamp >= cutoff
            }
            if delivery_id in self._deliveries:
                return False
            if len(self._deliveries) >= 1_000:
                oldest = min(self._deliveries, key=self._deliveries.get)
                self._deliveries.pop(oldest)
            self._deliveries[delivery_id] = now
            return True


def make_handler(application: WebhookApplication) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "UnraidTemplateSync/1.0"

        def log_message(self, format_string: str, *args: Any) -> None:
            LOG.info("%s - %s", self.client_address[0], format_string % args)

        def send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            encoded = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path != "/healthz":
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            status = application.worker.snapshot()
            hook_networks, refreshed_at = application.networks.snapshot()
            healthy = status["state"] != "error" and (
                not application.config.enforce_github_ips or bool(hook_networks)
            )
            self.send_json(
                HTTPStatus.OK if healthy else HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "healthy": healthy,
                    "sync": status,
                    "github_hook_network_count": len(hook_networks),
                    "github_hook_networks_refreshed_at": refreshed_at,
                },
            )

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path != "/webhook":
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return

            try:
                if not application.client_is_allowed(
                    self.client_address[0], self.headers.get("X-Forwarded-For")
                ):
                    self.send_json(HTTPStatus.FORBIDDEN, {"error": "source IP is not allowed"})
                    return
            except ValueError:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid forwarded address"})
                return

            try:
                content_length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                content_length = -1
            if content_length < 0 or content_length > application.config.max_body_bytes:
                self.send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "invalid body size"})
                return
            body = self.rfile.read(content_length)

            if not signature_is_valid(
                application.config.webhook_secret,
                body,
                self.headers.get("X-Hub-Signature-256"),
            ):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid signature"})
                return

            delivery_id = self.headers.get("X-GitHub-Delivery", "").strip()
            event = self.headers.get("X-GitHub-Event", "").strip()
            if not delivery_id or not event:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "missing GitHub headers"})
                return

            try:
                payload = json.loads(body)
                repository = payload["repository"]["full_name"]
            except (json.JSONDecodeError, KeyError, TypeError):
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid GitHub payload"})
                return

            if repository.lower() != application.config.github_repository.lower():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "repository is not allowed"})
                return

            if not application.remember_delivery(delivery_id):
                self.send_json(HTTPStatus.OK, {"status": "duplicate ignored"})
                return

            if event == "ping":
                self.send_json(HTTPStatus.OK, {"status": "pong"})
                return
            if event != "push":
                self.send_json(HTTPStatus.ACCEPTED, {"status": "event ignored"})
                return

            expected_ref = f"refs/heads/{application.config.github_branch}"
            if payload.get("ref") != expected_ref:
                self.send_json(HTTPStatus.ACCEPTED, {"status": "ref ignored"})
                return
            if payload.get("deleted") is True:
                self.send_json(HTTPStatus.ACCEPTED, {"status": "deleted ref ignored"})
                return

            queued = application.worker.enqueue(f"GitHub delivery {delivery_id}")
            self.send_json(
                HTTPStatus.ACCEPTED,
                {"status": "sync queued" if queued else "sync already queued"},
            )

    return Handler


def print_nginx_allowlist() -> None:
    networks = GithubHookNetworks(Path("/tmp/unused-github-hooks.json"), 21_600)
    request = urllib.request.Request(
        networks.meta_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "unraid-template-sync/1.0",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.load(response)
    for network in payload.get("hooks", []):
        print(f"allow {network};")
    print("deny all;")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--print-nginx-allowlist",
        action="store_true",
        help="print current GitHub webhook CIDRs as Nginx allow directives",
    )
    arguments = parser.parse_args()
    if arguments.print_nginx_allowlist:
        print_nginx_allowlist()
        return

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    config = Config.from_environment()
    config.state_dir.mkdir(parents=True, exist_ok=True)

    networks = GithubHookNetworks(
        config.state_dir / "github-hook-networks.json",
        config.github_meta_refresh_seconds,
    )
    networks.load_cache()
    if config.enforce_github_ips:
        try:
            networks.refresh()
        except Exception as error:
            LOG.error("Could not initially refresh GitHub hook networks: %s", error)
        threading.Thread(
            target=networks.refresh_forever,
            name="github-network-refresh",
            daemon=True,
        ).start()

    worker = SyncWorker(TemplateSynchronizer(config))
    worker.start()
    if config.sync_on_start:
        worker.enqueue("container startup")

    application = WebhookApplication(config, networks, worker)
    server = ThreadingHTTPServer(
        (config.listen_address, config.port),
        make_handler(application),
    )
    LOG.info("Listening on %s:%d", config.listen_address, config.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        networks.stop()
        server.server_close()


if __name__ == "__main__":
    main()
