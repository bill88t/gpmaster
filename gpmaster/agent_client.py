import os, socket, json, base64
from typing import Optional


def _socket_path() -> str:
    # Choose socket path using same heuristics as the agent.

    env_sock = os.environ.get("GPMASTER_AGENT_SOCKET")
    if env_sock:
        return env_sock

    candidates = []
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        candidates.append(xdg_runtime)

    xdg_state = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )
    candidates.append(xdg_state)

    candidates.append(f"/run/user/{os.getuid()}")
    candidates.append(f"/tmp/gpmaster-{os.getuid()}")

    for base in candidates:
        try:
            dirpath = os.path.join(base, "gpmaster")
            if os.path.isdir(dirpath) and os.access(
                dirpath, os.R_OK | os.W_OK | os.X_OK
            ):
                return os.path.join(dirpath, "agent.sock")
        except Exception:
            continue

    # Try reading state file written by the agent
    possible_state_files = [
        os.path.join(c, "gpmaster", "agent.socketpath") for c in candidates
    ]
    for sf in possible_state_files:
        try:
            if os.path.exists(sf):
                with open(sf, "r") as f:
                    p = f.read().strip()
                    if p:
                        return p
        except Exception:
            pass

    # Fallback to XDG_RUNTIME_DIR style even if it doesn't exist; caller will handle connection errors
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return os.path.join(runtime, "gpmaster", "agent.sock")


def _send(req: dict, timeout: float = 0.5) -> dict:
    path = _socket_path()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(path)
            s.sendall((json.dumps(req) + "\n").encode("utf-8"))
            f = s.makefile("rb")
            resp_line = f.readline()
            if not resp_line:
                return {"status": "ERROR", "message": "no response"}
            return json.loads(resp_line.decode("utf-8"))
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}


def get_cached(lockbox_path: str) -> Optional[bytes]:
    """Attempt to retrieve cached decrypted payload for a lockbox path.

    Returns raw bytes (JSON payload) on success or None on failure/not found.
    """
    resp = _send({"cmd": "GET", "path": lockbox_path})
    if resp.get("status") != "OK":
        return None
    try:
        return base64.b64decode(resp["data"])
    except Exception:
        return None


def set_cached(lockbox_path: str, data: bytes) -> bool:
    """Store raw decrypted payload (bytes) in the agent cache.

    Returns True on success, False otherwise. This is best-effort.
    """
    import base64 as _b64

    resp = _send(
        {
            "cmd": "SET",
            "path": lockbox_path,
            "data": _b64.b64encode(data).decode("ascii"),
        }
    )
    return resp.get("status") == "OK"
