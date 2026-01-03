import json
import os
import secrets
import subprocess
import time
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _env_str(name: str, default: str) -> str:
    val = os.environ.get(name)
    if val is None:
        return default
    val = str(val).strip()
    return val if val != "" else default


PROJECT = _env_str("BLACKCAT_OPERATOR_PROJECT", "minimal-prod")
PORT = int(_env_str("BLACKCAT_OPERATOR_PORT", "8090"))
ALLOW_ORIGIN = _env_str("BLACKCAT_OPERATOR_ALLOW_ORIGIN", "http://localhost:8088")
TIMEOUT_SEC = int(_env_str("BLACKCAT_OPERATOR_TIMEOUT_SEC", "600"))
COMPOSE_DIR = _env_str("BLACKCAT_OPERATOR_COMPOSE_DIR", "/opt/blackcat-operator/compose")
TOKEN_FILE = _env_str("BLACKCAT_OPERATOR_TOKEN_FILE", "/opt/blackcat-operator/shared/operator.token")
TOKEN_ENV = _env_str("BLACKCAT_OPERATOR_TOKEN", "")
TOKEN_HEADER = "X-BlackCat-Operator-Token"

RUN_LOCK = threading.Lock()


def _path(*parts: str) -> str:
    return os.path.join(*parts)


BASE_FILES = [
    _path(COMPOSE_DIR, "docker-compose.yml"),
    _path(COMPOSE_DIR, "docker-compose.demo.yml"),
]

OVERLAY = {
    "filesystem_tamper": _path(COMPOSE_DIR, "docker-compose.filesystem-tamper.yml"),
    "config_tamper": _path(COMPOSE_DIR, "docker-compose.config-tamper-restart.yml"),
    "manifest_tamper": _path(COMPOSE_DIR, "docker-compose.manifest-tamper-restart.yml"),
    "controller_swap": _path(COMPOSE_DIR, "docker-compose.controller-swap-restart.yml"),
    "rpc_outage": _path(COMPOSE_DIR, "docker-compose.rpc-outage.yml"),
    "byzantine_rpc": _path(COMPOSE_DIR, "docker-compose.byzantine-rpc.yml"),
}


SCENARIOS = {
    "reset_trusted": {
        "overlays": [],
        "steps": [["up", "-d", "--no-build", "--force-recreate", "app", "runner", "insecure"]],
    },
    "reset_hard": {
        "overlays": [],
        "steps": [["__wipe_demo_volumes__"], ["up", "-d", "--no-build", "--force-recreate", "app", "runner", "insecure"]],
    },
    "filesystem_tamper": {
        "overlays": [OVERLAY["filesystem_tamper"]],
        "steps": [["up", "-d", "--no-build", "--force-recreate", "app", "runner", "insecure"]],
    },
    "config_tamper": {
        "overlays": [OVERLAY["config_tamper"]],
        "steps": [["up", "-d", "--no-build", "--force-recreate", "app", "runner", "insecure"]],
    },
    "manifest_tamper": {
        "overlays": [OVERLAY["manifest_tamper"]],
        "steps": [["up", "-d", "--no-build", "--force-recreate", "app", "runner", "insecure"]],
    },
    "controller_swap": {
        "overlays": [OVERLAY["controller_swap"]],
        "steps": [["up", "-d", "--no-build", "--force-recreate", "app", "runner", "insecure"]],
    },
    "rpc_outage": {
        "overlays": [OVERLAY["rpc_outage"]],
        "steps": [["up", "-d", "--no-build", "--force-recreate", "app", "runner", "insecure"]],
    },
    "byzantine_rpc": {
        "overlays": [OVERLAY["byzantine_rpc"]],
        "steps": [["up", "-d", "--no-build", "--force-recreate", "app", "runner", "insecure"]],
    },
}


def _compose_prefix(overlays: list[str]) -> list[str]:
    cmd = ["docker", "compose", "-p", PROJECT]
    for f in BASE_FILES + overlays:
        cmd.extend(["-f", f])
    return cmd


def _run_compose(overlays: list[str], args: list[str]) -> dict:
    cmd = _compose_prefix(overlays) + args
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_SEC)
    ended = time.time()
    return {
        "cmd": cmd,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "elapsed_ms": int((ended - started) * 1000),
    }


def _run_cmd(cmd: list[str]) -> dict:
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_SEC)
    ended = time.time()
    return {
        "cmd": cmd,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "elapsed_ms": int((ended - started) * 1000),
    }


def _ensure_token() -> str:
    if TOKEN_ENV.strip() != "":
        return TOKEN_ENV.strip()

    path = TOKEN_FILE.strip()
    if path == "":
        return ""

    try:
        if os.path.isfile(path):
            with open(path, "rb") as f:
                raw = f.read().decode("utf-8", errors="ignore").strip()
            if raw != "":
                try:
                    os.chmod(path, 0o644)
                except Exception:
                    pass
                return raw
    except Exception:
        pass

    token = secrets.token_hex(16)
    try:
        parent = os.path.dirname(path)
        if parent != "":
            os.makedirs(parent, exist_ok=True)
        tmp = path + ".tmp-" + secrets.token_hex(6)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(token + "\n")
        try:
            os.chmod(tmp, 0o644)
        except Exception:
            pass
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o644)
        except Exception:
            pass
    except Exception:
        return token

    return token


TOKEN = _ensure_token()


def _volume(name: str) -> str:
    return f"{PROJECT}_{name}"


def _existing_volumes() -> set[str]:
    try:
        proc = subprocess.run(["docker", "volume", "ls", "--format", "{{.Name}}"], capture_output=True, text=True, timeout=TIMEOUT_SEC)
        if proc.returncode != 0:
            return set()
        out = proc.stdout or ""
        return set([line.strip() for line in out.splitlines() if line.strip() != ""])
    except Exception:
        return set()


def _wipe_demo_volumes() -> list[dict]:
    results: list[dict] = []
    results.append(_run_compose([], ["stop", "app", "runner", "insecure"]))
    # Volumes cannot be removed while referenced by stopped containers. Remove the containers first.
    results.append(_run_compose([], ["rm", "-f", "app", "runner", "insecure"]))

    wanted = [
        _volume("blackcat_etc"),
        _volume("blackcat_var"),
        _volume("blackcat_harness_logs"),
        _volume("blackcat_harness_reports"),
    ]
    existing = _existing_volumes()
    to_remove = [v for v in wanted if v in existing]
    if to_remove:
        results.append(_run_cmd(["docker", "volume", "rm", "-f"] + to_remove))
    else:
        results.append({"cmd": ["docker", "volume", "rm", "-f"] + wanted, "exit_code": 0, "stdout": "", "stderr": "(no volumes to remove)", "elapsed_ms": 0})

    return results


class Handler(BaseHTTPRequestHandler):
    server_version = "BlackCatDemoOperator/1.0"

    def _send_json(self, status: int, payload: dict) -> None:
        body = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", ALLOW_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", f"Content-Type,{TOKEN_HEADER}")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", ALLOW_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", f"Content-Type,{TOKEN_HEADER}")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(
                200,
                {
                    "ok": True,
                    "project": PROJECT,
                    "compose_dir": COMPOSE_DIR,
                    "token_configured": TOKEN.strip() != "",
                    "scenarios": sorted(list(SCENARIOS.keys())),
                },
            )
            return

        if parsed.path == "/run":
            q = urllib.parse.parse_qs(parsed.query)
            scenario = (q.get("scenario") or [""])[0].strip()
            self._handle_run(scenario)
            return

        self._send_json(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/run":
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length) if length > 0 else b""
            scenario = ""
            try:
                if raw.strip():
                    data = json.loads(raw.decode("utf-8"))
                    scenario = str(data.get("scenario") or "").strip()
            except Exception:
                scenario = ""
            self._handle_run(scenario)
            return
        self._send_json(404, {"ok": False, "error": "not_found"})

    def _handle_run(self, scenario: str) -> None:
        expected = TOKEN.strip()
        got = (self.headers.get(TOKEN_HEADER) or "").strip()
        if expected != "" and got != expected:
            self._send_json(401, {"ok": False, "error": "unauthorized"})
            return

        if scenario not in SCENARIOS:
            self._send_json(
                400,
                {
                    "ok": False,
                    "error": "unknown_scenario",
                    "scenario": scenario,
                    "available": sorted(list(SCENARIOS.keys())),
                },
            )
            return

        spec = SCENARIOS[scenario]
        overlays = list(spec.get("overlays") or [])
        steps = list(spec.get("steps") or [])

        results: list[dict] = []
        try:
            if not RUN_LOCK.acquire(blocking=False):
                self._send_json(409, {"ok": False, "error": "busy"})
                return

            for args in steps:
                if args == ["__wipe_demo_volumes__"]:
                    results.extend(_wipe_demo_volumes())
                else:
                    results.append(_run_compose(overlays, list(args)))
        except subprocess.TimeoutExpired:
            self._send_json(504, {"ok": False, "error": "timeout", "scenario": scenario, "results": results})
            return
        except Exception as e:
            self._send_json(500, {"ok": False, "error": "run_failed", "scenario": scenario, "detail": str(e), "results": results})
            return
        finally:
            try:
                RUN_LOCK.release()
            except Exception:
                pass

        ok = all(r.get("exit_code") == 0 for r in results)
        self._send_json(200 if ok else 500, {"ok": ok, "scenario": scenario, "project": PROJECT, "results": results})


def main() -> None:
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[operator] listening on 0.0.0.0:{PORT} (project={PROJECT})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
