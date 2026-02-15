import argparse, json, os, sys, time, termios, tty, select
from pathlib import Path

import base64, re, hmac, hashlib

from .lockbox import Lockbox

try:
    import pyotp

    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False


BASE32_RE = re.compile(r"^[A-Z2-7]+=*$", re.IGNORECASE)


def normalize_totp_secret(secret: str) -> str:
    s = secret.strip()

    # Treat strings that look like base32 (case-insensitive) as base32
    if BASE32_RE.fullmatch(s):
        # allow lowercase base32 and missing padding
        s_b32 = s.rstrip("=")
        pad = (-len(s_b32)) % 8
        if pad:
            s_b32 += "=" * pad
        raw = base64.b32decode(s_b32, casefold=True)
    else:
        # Try flexible base64 decoding: support URL-safe alphabet and missing padding
        b = s.encode("ascii")
        b = b.replace(b"-", b"+").replace(b"_", b"/")
        pad = (-len(b)) % 4
        if pad:
            b += b"=" * pad
        raw = base64.b64decode(b)

    # Return base32 (uppercase) without padding
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def totp_from_base64(secret_b64: str, digits: int = 6, period: int = 30) -> str:
    # decode base64 (flexible: urlsafe, missing padding)
    b = secret_b64.strip().encode("ascii")
    b = b.replace(b"-", b"+").replace(b"_", b"/")
    pad = (-len(b)) % 4
    if pad:
        b += b"=" * pad
    secret = base64.b64decode(b)

    # calculate counter
    counter = int(time.time() // period)
    counter_bytes = counter.to_bytes(8, byteorder="big")

    # HMAC-SHA1
    hmac_digest = hmac.new(secret, counter_bytes, hashlib.sha1).digest()

    # dynamic truncation
    offset = hmac_digest[-1] & 0x0F
    code_int = (
        (hmac_digest[offset] & 0x7F) << 24
        | (hmac_digest[offset + 1] & 0xFF) << 16
        | (hmac_digest[offset + 2] & 0xFF) << 8
        | (hmac_digest[offset + 3] & 0xFF)
    )

    return str(code_int % (10**digits)).zfill(digits)


def get_default_lockbox_path() -> str:
    """Get default lockbox path from environment or default location."""
    env_path = os.environ.get("GPMASTER_LOCKBOX_PATH")
    if env_path:
        return os.path.expanduser(env_path)
    return str(Path.home() / ".local" / "state" / "gpmaster.gpb")


def interactive_totp_viewer(lockbox, quiet):
    """Interactive TOTP viewer with timer."""
    secrets = lockbox.dump_secrets()

    totp_getters = {}
    for name, value in secrets.items():
        try:
            s = value.strip()
            if BASE32_RE.fullmatch(s):
                norm = normalize_totp_secret(value)
                # capture norm in default arg
                totp_getters[name] = lambda n=norm: pyotp.TOTP(n).now()
            else:
                totp_getters[name] = lambda v=value: totp_from_base64(v)
        except Exception:
            pass

    if not totp_getters:
        print("[GPMASTER:] No valid TOTP secrets found", file=sys.stderr)
        return

    old_settings = termios.tcgetattr(sys.stdin)
    try:
        tty.setcbreak(sys.stdin.fileno())

        print("\033[2J\033[H", end="", flush=True)
        print("[GPMASTER:] Interactive TOTP Viewer - Press any key to exit\n")

        last_code_time = 0
        while True:
            current_time = time.time()
            totp_period = 30
            remaining = totp_period - (int(current_time) % totp_period)

            codes_changed = int(current_time) // totp_period != last_code_time
            if codes_changed:
                print("\033[H", end="", flush=True)
                print("[GPMASTER:] Interactive TOTP Viewer - Press any key to exit")
                print(f"[GPMASTER:] Time remaining: {remaining}s")

                for name, getter in totp_getters.items():
                    try:
                        code = getter()
                    except Exception:
                        code = "Invalid TOTP"
                    print(f"\n{name}: {code}")

                last_code_time = int(current_time) // totp_period
            else:
                print(
                    f"\033[2;0H[GPMASTER:] Time remaining: {remaining}s \010",
                    end="",
                    flush=True,
                )

            if select.select([sys.stdin], [], [], 0.1)[0]:
                sys.stdin.read(1)
                print("\033[2J\033[H", end="", flush=True)
                break

            time.sleep(0.1)

    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        print("\033[2J\033[H", end="", flush=True)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="GPMaster - GPG-backed lockbox for secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-l",
        "--lockbox",
        default=get_default_lockbox_path(),
        help="Path to lockbox file (default: $GPMASTER_LOCKBOX_PATH or ~/.local/state/gpmaster.gpb)",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    parser.add_argument(
        "--scripted",
        action="store_true",
        help="Scripted mode: non-interactive mode, suppress non-output messages",
    )

    parser.add_argument(
        "--no-agent",
        action="store_true",
        help="Do not use the gpmaster agent for caching decrypted lockbox data",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    create_parser = subparsers.add_parser("create", help="Create a new lockbox")
    create_parser.add_argument("key_id", help="GPG key ID to use for encryption")

    add_parser = subparsers.add_parser("add", help="Add a secret")
    add_parser.add_argument("name", help="Secret name")
    add_parser.add_argument("--totp", action="store_true", help="Mark as TOTP secret")
    add_parser.add_argument("--key-id", help="GPG key ID (for auto-creating lockbox)")

    get_parser = subparsers.add_parser("get", help="Get a secret")
    get_parser.add_argument("name", help="Secret name")
    get_parser.add_argument(
        "--totp-code", action="store_true", help="Generate TOTP code"
    )
    get_parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Interactive TOTP viewer (shows timer and cycling codes)",
    )

    rename_parser = subparsers.add_parser("rename", help="Rename a secret")
    rename_parser.add_argument("old_name", help="Current secret name")
    rename_parser.add_argument("new_name", help="New secret name")

    delete_parser = subparsers.add_parser("delete", help="Delete a secret")
    delete_parser.add_argument("name", help="Secret name")

    subparsers.add_parser("info", help="Show lockbox info and verify integrity")

    subparsers.add_parser("note", help="Edit notes document (signed)")

    subparsers.add_parser("validate", help="Validate lockbox integrity")

    rekey_parser = subparsers.add_parser("rekey", help="Change encryption key")
    rekey_parser.add_argument("new_key_id", help="New GPG key ID")

    dump_parser = subparsers.add_parser("dump", help="Dump all secrets")
    dump_parser.add_argument(
        "--format",
        "-f",
        choices=["list", "json", "sh"],
        default="list",
        help="Output format (default: list)",
    )

    file_parser = subparsers.add_parser("file", help="File operations")
    file_subparsers = file_parser.add_subparsers(
        dest="file_command", help="File commands"
    )

    file_add_parser = file_subparsers.add_parser("add", help="Add a file to the vault")
    file_add_parser.add_argument("path", help="Path to file to add")
    file_add_parser.add_argument(
        "--keep-source", action="store_true", help="Keep original file after adding"
    )
    file_add_parser.add_argument(
        "--key-id", help="GPG key ID (for auto-creating lockbox)"
    )

    file_remove_parser = file_subparsers.add_parser(
        "remove", help="Remove a file from the vault"
    )
    file_remove_parser.add_argument("filename", help="Filename to remove")

    file_subparsers.add_parser("list", help="List all files in the vault")

    file_get_parser = file_subparsers.add_parser(
        "get", help="Retrieve a file from the vault"
    )
    file_get_parser.add_argument("filename", help="Filename to retrieve")
    file_get_parser.add_argument(
        "--text", action="store_true", help="Output as text to stdout"
    )
    file_get_parser.add_argument("--path", help="Save to specific file path")
    file_get_parser.add_argument(
        "--tmp", action="store_true", help="Save to tmpfile in /tmp"
    )

    args = parser.parse_args()

    if args.scripted:
        args.quiet = True
        sys.stderr = open(os.devnull, "w")

    if os.environ.get("GPMASTER_QUIET"):
        args.quiet = True

    if (not args.command) and not args.scripted:
        parser.print_help()
        return 0

    try:
        lockbox = Lockbox(
            args.lockbox,
            quiet=args.quiet,
            use_agent=not getattr(args, "no_agent", False),
        )

        if args.command == "create":
            lockbox.create(args.key_id)

        elif args.command == "add":
            if args.totp and not TOTP_AVAILABLE:
                print(
                    "[GPMASTER:] Error: pyotp not installed",
                    file=sys.stderr,
                )
                return 1

            secret = input("[GPMASTER:] Enter secret: " if not args.quiet else "")
            if args.totp:
                try:
                    s = secret.strip()
                    if BASE32_RE.fullmatch(s):
                        secret = normalize_totp_secret(secret)
                        pyotp.TOTP(secret)
                    else:
                        # validate base64 by attempting to compute a code
                        _ = totp_from_base64(secret)
                except Exception as e:
                    print(f"[GPMASTER:] Invalid TOTP secret: {e}", file=sys.stderr)
                    return 1

            # Auto-create lockbox if key provided
            auto_key = args.key_id or os.environ.get("GPMASTER_KEY_ID")
            lockbox.add_secret(
                args.name, secret, is_totp=args.totp, auto_create_key=auto_key
            )

        elif args.command == "get":
            secret, is_totp = lockbox.get_secret(args.name)

            if secret is None:
                print(f"[GPMASTER:] Secret not found: {args.name}", file=sys.stderr)
                return 1

            if args.interactive:
                if not TOTP_AVAILABLE:
                    print("[GPMASTER:] Error: pyotp not installed", file=sys.stderr)
                    return 1
                if not is_totp:
                    print(
                        f"[GPMASTER:] Error: {args.name} is not a TOTP secret",
                        file=sys.stderr,
                    )
                    return 1

                # Create a temporary lockbox dict with just this secret
                temp_secrets = {args.name: secret}
                old_dump = lockbox.dump_secrets
                lockbox.dump_secrets = lambda: temp_secrets
                interactive_totp_viewer(lockbox, args.quiet)
                lockbox.dump_secrets = old_dump
            elif args.totp_code or is_totp:
                if not TOTP_AVAILABLE:
                    print("[GPMASTER:] Error: pyotp not installed", file=sys.stderr)
                    return 1

                try:
                    s = secret.strip()
                    if BASE32_RE.fullmatch(s):
                        code = pyotp.TOTP(normalize_totp_secret(secret)).now()
                    else:
                        code = totp_from_base64(secret)
                    print(code)
                except Exception as e:
                    print(
                        f"[GPMASTER:] Failed to generate TOTP code: {e}",
                        file=sys.stderr,
                    )
                    return 1
            else:
                print(secret)

        elif args.command == "rename":
            lockbox.rename_secret(args.old_name, args.new_name)

        elif args.command == "delete":
            lockbox.delete_secret(args.name)

        elif args.command == "info":
            titles, note_content, note_signature, key_id = lockbox.get_info()

            if not args.quiet:
                print(f"[GPMASTER:] Lockbox encrypted with key: {key_id}")

            # Separate files from secrets
            files = [t for t in titles if t.startswith("_FILE_")]
            secrets = [t for t in titles if not t.startswith("_FILE_")]

            if not args.quiet and len(secrets) > 0:
                print(f"[GPMASTER:] Secrets ({len(secrets)}):")
            for secret in secrets:
                print(f"  {secret}")

            if not args.quiet and len(files) > 0:
                if len(secrets):
                    print()
                print(f"[GPMASTER:] Files ({len(files)}):")
            for file_key in files:
                filename = file_key[6:]  # Remove "_FILE_" prefix
                print(f"  {filename}")

            if note_content is not None and not args.quiet:
                print("\n[GPMASTER:] Note:")
                print(note_content)

                if note_signature:
                    data_to_verify = note_content.encode("utf-8")
                    valid, signer_key = lockbox.gpg.verify(
                        data_to_verify, note_signature
                    )
                    if valid:
                        print(
                            f"[GPMASTER:] Note signature valid (signed by: {signer_key})"
                        )
                    else:
                        print(f"[GPMASTER:] Note signature INVALID")
                else:
                    print(f"[GPMASTER:] Note present but not signed")

        elif args.command == "note":
            lockbox.edit_note()

        elif args.command == "validate":
            valid = lockbox.validate()
            return 0 if valid else 1

        elif args.command == "rekey":
            lockbox.rekey(args.new_key_id)

        elif args.command == "dump":
            secrets = lockbox.dump_secrets()
            if args.format == "list":
                for name, value in secrets.items():
                    print(f"{name}: {value}")
            elif args.format == "json":
                print(json.dumps(secrets, indent=2))
            elif args.format == "sh":
                for name, value in secrets.items():
                    safe_name = (
                        name.replace("-", "_")
                        .replace(".", "_")
                        .replace(" ", "_")
                        .upper()
                    )
                    safe_value = value.replace("'", "'\\''")
                    print(f"{safe_name}='{safe_value}'")

        elif args.command == "file":
            if not args.file_command:
                print(
                    "[GPMASTER:] Error: file subcommand required (add, remove, list, get)",
                    file=sys.stderr,
                )
                return 1

            if args.file_command == "add":
                auto_key = args.key_id or os.environ.get("GPMASTER_KEY_ID")
                lockbox.add_file(
                    args.path, keep_source=args.keep_source, auto_create_key=auto_key
                )

            elif args.file_command == "remove":
                lockbox.remove_file(args.filename)

            elif args.file_command == "list":
                files = lockbox.list_files()
                if not args.quiet:
                    print(f"[GPMASTER:] Files in vault ({len(files)}):")
                for filename in files:
                    print(f"  {filename}")

            elif args.file_command == "get":
                file_data = lockbox.get_file(args.filename)

                if file_data is None:
                    print(
                        f"[GPMASTER:] File not found: {args.filename}", file=sys.stderr
                    )
                    return 1

                if args.text:
                    # Output as text
                    sys.stdout.buffer.write(file_data)
                elif args.path:
                    # Save to specific path
                    target_path = Path(args.path)
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(target_path, "wb") as f:
                        f.write(file_data)
                    if not args.quiet:
                        print(f"[GPMASTER:] File saved to: {args.path}")
                elif args.tmp:
                    # Save to tmpfile
                    uid = os.getuid()
                    tmpfile_path = f"/tmp/gpmaster.{uid}.{args.filename}"
                    with open(tmpfile_path, "wb") as f:
                        f.write(file_data)
                    if not args.quiet:
                        print(f"[GPMASTER:] File saved to: {tmpfile_path}")
                    else:
                        print(tmpfile_path)
                else:
                    # Default: output as text to stdout
                    sys.stdout.buffer.write(file_data)

        return 0

    except Exception as e:
        if not args.scripted:
            print(f"[GPMASTER:] Error: {e}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
