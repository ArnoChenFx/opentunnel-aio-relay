#!/usr/bin/env python3
"""Minimal management API and UI for opentunnel serve in Docker."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

BIN = os.environ.get("OPENTUNNEL_BIN", "/usr/local/bin/opentunnel")
ADMIN_PORT = int(os.environ.get("OT_CLIENT_ADMIN_PORT", "9080"))
ADMIN_TOKEN = os.environ.get("OT_CLIENT_ADMIN_TOKEN", "").strip()
STATIC_DIR = Path(__file__).resolve().parent / "static"

ROUTE_LINE = re.compile(
    r"^(?P<name>@|[a-z0-9-]+)\s+[→\->]+\s+(?P<target>.+?)\s*$"
)
# status(1) prints "fqdn  →  host:port" (Unicode arrow, padded spaces)
STATUS_MAP_LINE = re.compile(r"^(?P<host>\S+)\s+[→\->]+\s+(?P<target>.+?)\s*$")
URL_RE = re.compile(r"https?://[^\s]+")


def run_opentunnel(*args: str, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    return subprocess.run(
        [BIN, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


def active_profile() -> str:
    return os.environ.get("OPENTUNNEL_PROFILE", "default")


def discover_profiles() -> list[str]:
    """Profiles seen in config or data dirs (one tunnel identity per profile)."""
    names: set[str] = set()
    config_root = Path(os.environ.get("XDG_CONFIG_HOME", "/data/config")) / "opentunnel"
    data_root = Path(os.environ.get("XDG_DATA_HOME", "/data/data")) / "opentunnel"
    if config_root.is_dir():
        for path in config_root.glob("*.toml"):
            if path.stem:
                names.add(path.stem)
    if data_root.is_dir():
        for path in data_root.iterdir():
            if path.is_dir() and not path.name.startswith("."):
                names.add(path.name)
    if not names:
        names.add(active_profile())
    return sorted(names)


def status_text(profile: str) -> str:
    proc = run_opentunnel("status", "--profile", profile)
    return ((proc.stdout or "") + (proc.stderr or "")).strip()


def collect_status() -> tuple[str, list[str], int]:
    profiles = discover_profiles()
    parts: list[str] = []
    exit_code = 0
    for profile in profiles:
        text = status_text(profile)
        if len(profiles) > 1:
            parts.append(f"=== profile: {profile} ===\n{text}")
        else:
            parts.append(text)
    return "\n\n".join(parts).strip(), profiles, exit_code


def is_status_route_line(line: str) -> bool:
    return STATUS_MAP_LINE.match(line.strip()) is not None


def route_name_from_host(host: str, tunnel_hostname: str | None) -> str:
    host = host.strip().lower()
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix) :]
    if not tunnel_hostname:
        return host.split(".")[0] if host else "@"
    th = tunnel_hostname.strip().lower()
    if host == th:
        return "@"
    suffix = "." + th
    if host.endswith(suffix):
        prefix = host[: -len(suffix)]
        return prefix if prefix else "@"
    return host.split(".")[0]


def parse_routes(text: str) -> list[dict[str, str]]:
    routes: list[dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("No routes"):
            continue
        m = ROUTE_LINE.match(line)
        if m:
            routes.append({"name": m.group("name"), "target": m.group("target")})
    return routes


def parse_status_map_routes(text: str, tunnel_hostname: str | None) -> list[dict[str, str]]:
    routes: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        m = STATUS_MAP_LINE.match(line.strip())
        if not m:
            continue
        host = m.group("host")
        target = m.group("target").strip()
        name = route_name_from_host(host, tunnel_hostname)
        if name in seen:
            continue
        seen.add(name)
        routes.append({"name": name, "target": target})
    return routes


def merge_routes(*groups: list[dict[str, str]]) -> list[dict[str, str]]:
    by_name: dict[str, dict[str, str]] = {}
    for group in groups:
        for route in group:
            by_name[route["name"]] = route
    return [by_name[k] for k in sorted(by_name.keys(), key=lambda n: (n != "@", n))]


def status_summary(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or is_status_route_line(stripped):
            continue
        lines.append(line.rstrip())
    return "\n".join(lines).strip()


def parse_status(text: str) -> dict[str, Any]:
    info: dict[str, Any] = {
        "raw": text,
        "summary": "",
        "profile": None,
        "tunnel_id": None,
        "hostname": None,
        "connected": None,
        "service": None,
        "routes": [],
    }
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Profile:"):
            info["profile"] = line.split(":", 1)[1].strip()
        elif line.startswith("Tunnel ID:"):
            info["tunnel_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("Hostname:"):
            info["hostname"] = line.split(":", 1)[1].strip()
        elif line.startswith("Connected"):
            info["connected"] = line
            m = URL_RE.search(line)
            if m:
                info["bridge_url"] = m.group(0)
        elif line.startswith("Service:"):
            info["service"] = line.split(":", 1)[1].strip()
    info["routes"] = merge_routes(
        parse_routes(text),
        parse_status_map_routes(text, info.get("hostname")),
    )
    info["summary"] = status_summary(text)
    return info


def routes_for_profile() -> tuple[list[dict[str, str]], int, str]:
    profile = active_profile()
    status_raw = status_text(profile)
    status = parse_status(status_raw)
    proc = run_opentunnel("route", "list", "--profile", profile)
    list_text = (proc.stdout or "") + (proc.stderr or "")
    routes = merge_routes(parse_routes(list_text), status.get("routes", []))
    hostname = status.get("hostname")
    for route in routes:
        route["url"] = public_url(hostname, route["name"])
    return routes, proc.returncode, list_text.strip()


def api_endpoint() -> tuple[str, int | None]:
    """Scheme and port from OPENTUNNEL_API (visitor TLS uses the same port as the API)."""
    raw = os.environ.get("OPENTUNNEL_API", "").strip()
    if not raw:
        return "https", None
    parsed = urlparse(raw)
    scheme = parsed.scheme or "https"
    return scheme, parsed.port


def public_port_suffix() -> str:
    scheme, port = api_endpoint()
    if port is None:
        return ""
    default = 443 if scheme == "https" else 80
    if port == default:
        return ""
    return f":{port}"


def public_url_meta() -> dict[str, Any]:
    scheme, port = api_endpoint()
    suffix = public_port_suffix()
    exposed_port: int | None = port
    if not suffix:
        exposed_port = None
    return {"public_scheme": scheme, "public_port": exposed_port}


def enrich_urls_with_public_port(text: str) -> str:
    suffix = public_port_suffix()
    if not suffix:
        return text

    def repl(match: re.Match[str]) -> str:
        url = match.group(0)
        parsed = urlparse(url)
        if parsed.port is not None or not parsed.hostname:
            return url
        return f"{parsed.scheme}://{parsed.hostname}{suffix}"

    return URL_RE.sub(repl, text)


def public_url(hostname: str | None, route_name: str) -> str | None:
    if not hostname:
        return None
    scheme, _ = api_endpoint()
    host = hostname.strip()
    suffix = public_port_suffix()
    if route_name == "@":
        return f"{scheme}://{host}{suffix}"
    return f"{scheme}://{route_name}.{host}{suffix}"


def json_response(handler: BaseHTTPRequestHandler, status: int, body: Any) -> None:
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class Handler(BaseHTTPRequestHandler):
    server_version = "opentunnel-mgmt/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _authorized(self) -> bool:
        if not ADMIN_TOKEN:
            return True
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {ADMIN_TOKEN}":
            return True
        if self.headers.get("X-Admin-Token") == ADMIN_TOKEN:
            return True
        return False

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON: {exc}") from exc

    def _require_auth(self) -> bool:
        if self._authorized():
            return True
        json_response(self, 401, {"error": "unauthorized"})
        return False

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._serve_static("index.html", "text/html; charset=utf-8")
            return
        if path == "/health":
            json_response(self, 200, {"ok": True})
            return
        if path == "/api/status":
            if not self._require_auth():
                return
            _raw, profiles, _exit = collect_status()
            profile = active_profile()
            active_raw = status_text(profile)
            body = parse_status(active_raw)
            if len(profiles) > 1:
                chunks = [
                    f"=== profile: {p} ===\n{status_summary(status_text(p))}" for p in profiles
                ]
                body["summary"] = "\n\n".join(chunks)
            else:
                body["summary"] = status_summary(active_raw)
            body["summary"] = enrich_urls_with_public_port(body.get("summary") or "")
            body["profiles"] = profiles
            body["active_profile"] = profile
            body.update(public_url_meta())
            for route in body.get("routes", []):
                route["url"] = public_url(body.get("hostname"), route["name"])
            json_response(self, 200, body)
            return
        if path == "/api/routes":
            if not self._require_auth():
                return
            routes, exit_code, list_raw = routes_for_profile()
            payload: dict[str, Any] = {
                "routes": routes,
                "exit_code": exit_code,
                "raw": list_raw,
            }
            payload.update(public_url_meta())
            json_response(self, 200, payload)
            return
        json_response(self, 404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._require_auth():
            return
        path = self.path.split("?", 1)[0]
        if path != "/api/routes":
            json_response(self, 404, {"error": "not found"})
            return
        try:
            payload = self._read_json()
        except ValueError as exc:
            json_response(self, 400, {"error": str(exc)})
            return
        target = str(payload.get("target", "")).strip()
        name = payload.get("name")
        route_name = str(name).strip() if name is not None else ""
        if route_name and not re.fullmatch(r"@|[a-z0-9-]+", route_name):
            json_response(
                self,
                400,
                {"error": "name must be @ or a lowercase DNS label (a-z, 0-9, hyphen)"},
            )
            return
        if not target:
            json_response(self, 400, {"error": "target is required"})
            return
        profile = active_profile()
        args = ["route", "add", target, "--profile", profile]
        if route_name:
            args.extend(["--name", route_name])
        proxy = payload.get("proxy_protocol")
        if proxy in ("v1", "v2"):
            args.extend(["--proxy-protocol", proxy])
        proc = run_opentunnel(*args, timeout=600.0)
        out = (proc.stdout or "") + (proc.stderr or "")
        url_match = URL_RE.search(out)
        cli_url = url_match.group(0) if url_match else None
        url = enrich_urls_with_public_port(cli_url) if cli_url else None
        if not url and route_name:
            status = parse_status(status_text(profile))
            url = public_url(status.get("hostname"), route_name)
        json_response(
            self,
            200 if proc.returncode == 0 else 502,
            {
                "ok": proc.returncode == 0,
                "exit_code": proc.returncode,
                "output": out.strip(),
                "url": url,
            },
        )

    def do_PUT(self) -> None:  # noqa: N802
        self.do_POST()

    def do_DELETE(self) -> None:  # noqa: N802
        if not self._require_auth():
            return
        path = self.path.split("?", 1)[0]
        if not path.startswith("/api/routes/"):
            json_response(self, 404, {"error": "not found"})
            return
        name = unquote(path[len("/api/routes/") :]).strip()
        if not name:
            json_response(self, 400, {"error": "route name required"})
            return
        proc = run_opentunnel("route", "remove", name, "--profile", active_profile())
        out = (proc.stdout or "") + (proc.stderr or "")
        json_response(
            self,
            200 if proc.returncode == 0 else 502,
            {"ok": proc.returncode == 0, "exit_code": proc.returncode, "output": out.strip()},
        )

    def _serve_static(self, name: str, content_type: str) -> None:
        file_path = STATIC_DIR / name
        if not file_path.is_file():
            json_response(self, 404, {"error": "missing static asset"})
            return
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    host = "0.0.0.0"
    httpd = ThreadingHTTPServer((host, ADMIN_PORT), Handler)
    print(f"listening on http://{host}:{ADMIN_PORT}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
