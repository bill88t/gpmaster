import os, socket, struct, json, base64, hashlib, secrets, sys, threading, signal
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None


def _lock_memory() -> None:
    try:
        import ctypes

        libc = ctypes.CDLL("libc.so.6")
        MCL_CURRENT = 1
        MCL_FUTURE = 2
        libc.mlockall(MCL_CURRENT | MCL_FUTURE)
    except Exception:
        # Not fatal; best-effort
        pass


class AgentServer:
    def __init__(self, socket_path: str):
        if AESGCM is None:
            print(
                "[GPMASTER:] cryptography package is required for gpmaster-agent",
                file=sys.stderr,
            )
            sys.exit(1)

        self.socket_path = socket_path
        self._storage = {}  # mapping (path, key_hex) -> base64(nonce||ciphertext)
        self._running = False
        self._sock = None

    def start(self) -> None:
        _lock_memory()

        sockdir = os.path.dirname(self.socket_path)
        os.makedirs(sockdir, mode=0o700, exist_ok=True)

        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except Exception:
                pass

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(self.socket_path)
        try:
            os.chmod(self.socket_path, 0o600)
        except Exception:
            pass

        self._sock.listen(8)
        self._running = True

        def _serve():
            while self._running:
                try:
                    conn, _ = self._sock.accept()
                except Exception:
                    if not self._running:
                        break
                    continue
                th = threading.Thread(
                    target=self._handle_conn, args=(conn,), daemon=True
                )
                th.start()

        t = threading.Thread(target=_serve, daemon=True)
        t.start()

    def stop(self) -> None:
        self._running = False
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        try:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
        except Exception:
            pass

    def _peer_exec_hash(self, conn: socket.socket):
        try:
            ucred = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            pid, uid, gid = struct.unpack("3i", ucred)
            exe_link = f"/proc/{pid}/exe"
            exe_path = os.readlink(exe_link)
            with open(exe_path, "rb") as f:
                data = f.read()
            return hashlib.sha256(data).digest()
        except Exception:
            try:
                ucred = conn.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                )
                pid, uid, gid = struct.unpack("3i", ucred)
                return hashlib.sha256(f"{uid}-{gid}".encode()).digest()
            except Exception:
                return None

    def _handle_conn(self, conn: socket.socket):
        try:
            key_digest = self._peer_exec_hash(conn)
            if key_digest is None:
                conn.sendall(
                    json.dumps(
                        {
                            "status": "ERROR",
                            "message": "unable to determine peer identity",
                        }
                    ).encode()
                    + b"\n"
                )
                return

            key_hex = key_digest.hex()

            f = conn.makefile("rb")
            line = f.readline()
            if not line:
                return

            try:
                req = json.loads(line.decode("utf-8"))
            except Exception:
                conn.sendall(
                    json.dumps(
                        {"status": "ERROR", "message": "invalid request"}
                    ).encode()
                    + b"\n"
                )
                return

            cmd = req.get("cmd")
            path = req.get("path")

            # Basic logging for debugging (to stderr; systemd will capture)
            try:
                sys.stderr.write(f"[GPMASTER:] gpmaster-agent: cmd={cmd} path={path}\n")
            except Exception:
                pass

            if cmd == "GET":
                stored = self._storage.get((path, key_hex))
                if not stored:
                    resp = {"status": "NOTFOUND"}
                else:
                    try:
                        raw = base64.b64decode(stored)
                        nonce = raw[:12]
                        ct = raw[12:]
                        aes = AESGCM(key_digest)
                        plaintext = aes.decrypt(nonce, ct, None)
                        resp = {
                            "status": "OK",
                            "data": base64.b64encode(plaintext).decode(),
                        }
                    except Exception as e:
                        resp = {"status": "ERROR", "message": str(e)}

            elif cmd == "SET":
                data_b64 = req.get("data")
                if not data_b64:
                    resp = {"status": "ERROR", "message": "no data"}
                else:
                    try:
                        payload = base64.b64decode(data_b64)
                        aes = AESGCM(key_digest)
                        nonce = secrets.token_bytes(12)
                        ct = aes.encrypt(nonce, payload, None)
                        stored_b64 = base64.b64encode(nonce + ct).decode()
                        self._storage[(path, key_hex)] = stored_b64
                        resp = {"status": "OK"}
                    except Exception as e:
                        resp = {"status": "ERROR", "message": str(e)}
            else:
                resp = {"status": "ERROR", "message": "unknown command"}

            conn.sendall((json.dumps(resp) + "\n").encode())
        finally:
            try:
                conn.close()
            except Exception:
                pass


def _choose_socket_path() -> str:
    """
    Order of preference:
      - GPMASTER_AGENT_SOCKET (override)
      - $XDG_RUNTIME_DIR/gpmaster
      - $XDG_STATE_HOME/gpmaster (or ~/.local/state)
      - /run/user/$UID/gpmaster
      - /tmp/gpmaster-$UID
    """

    env_sock = os.environ.get("GPMASTER_AGENT_SOCKET")
    if env_sock:
        return env_sock

    candidates = []
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        candidates.append(xdg_runtime)

    xdg_state = os.environ.get("XDG_STATE_HOME") or str(
        Path.home() / ".local" / "state"
    )
    candidates.append(xdg_state)

    candidates.append(f"/run/user/{os.getuid()}")
    candidates.append(f"/tmp/gpmaster-{os.getuid()}")

    for base in candidates:
        try:
            dirpath = os.path.join(base, "gpmaster")
            os.makedirs(dirpath, mode=0o700, exist_ok=True)
            if os.access(dirpath, os.W_OK | os.X_OK):
                return os.path.join(dirpath, "agent.sock")
        except PermissionError:
            continue
        except Exception:
            continue

    tmp = f"/tmp/gpmaster-{os.getuid()}"
    try:
        os.makedirs(tmp, mode=0o700, exist_ok=True)
    except Exception:
        pass
    return os.path.join(tmp, "agent.sock")


def main() -> None:
    socket_path = _choose_socket_path()
    server = AgentServer(socket_path)

    try:
        state_dir = os.path.dirname(socket_path)
        state_file = os.path.join(state_dir, "agent.socketpath")
        with open(state_file, "w") as sf:
            sf.write(socket_path)
        os.chmod(state_file, 0o600)
    except Exception:
        pass

    def _shutdown(signum, frame):
        try:
            if os.path.exists(state_file):
                os.unlink(state_file)
        except Exception:
            pass
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    server.start()

    try:
        while True:
            signal.pause()
    except Exception:
        try:
            if os.path.exists(state_file):
                os.unlink(state_file)
        except Exception:
            pass
        server.stop()


if __name__ == "__main__":
    main()
