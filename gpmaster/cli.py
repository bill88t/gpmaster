import argparse
import json
import os
import sys
import time
import termios
import tty
import select
from pathlib import Path

from .lockbox import Lockbox

try:
    import pyotp

    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False


def get_default_lockbox_path() -> str:
    """Get default lockbox path from environment or default location."""
    env_path = os.environ.get("GPMASTER_LOCKBOX_PATH")
    if env_path:
        return os.path.expanduser(env_path)
    return str(Path.home() / ".local" / "state" / "gpmaster.gpb")


def interactive_totp_viewer(lockbox, quiet):
    """Interactive TOTP viewer with timer."""
    secrets = lockbox.dump_secrets()

    totp_secrets = {}
    for name, value in secrets.items():
        try:
            totp = pyotp.TOTP(value)
            totp_secrets[name] = totp
        except Exception:
            pass

    if not totp_secrets:
        print("No valid TOTP secrets found", file=sys.stderr)
        return

    old_settings = termios.tcgetattr(sys.stdin)
    try:
        tty.setcbreak(sys.stdin.fileno())

        print("\033[2J\033[H", end="", flush=True)
        print("Interactive TOTP Viewer - Press any key to exit\n")

        last_code_time = 0
        while True:
            current_time = time.time()
            totp_period = 30
            remaining = totp_period - (int(current_time) % totp_period)

            codes_changed = int(current_time) // totp_period != last_code_time
            if codes_changed:
                print("\033[H", end="", flush=True)
                print("Interactive TOTP Viewer - Press any key to exit")
                print(f"Time remaining: {remaining}s")

                for name, totp in totp_secrets.items():
                    code = totp.now()
                    print(f"\n{name}: {code}")

                last_code_time = int(current_time) // totp_period
            else:
                print(f"\033[2;0HTime remaining: {remaining}s", end="", flush=True)

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

    args = parser.parse_args()

    if args.quiet or os.environ.get("GPMASTER_QUIET"):
        args.quiet = True

    if not args.command:
        parser.print_help()
        return 1

    try:
        lockbox = Lockbox(args.lockbox, quiet=args.quiet)

        if args.command == "create":
            lockbox.create(args.key_id)

        elif args.command == "add":
            if args.totp and not TOTP_AVAILABLE:
                print(
                    "Error: pyotp not installed. Install it for TOTP support.",
                    file=sys.stderr,
                )
                return 1

            secret = input("Enter secret: " if not args.quiet else "")
            if args.totp:
                try:
                    pyotp.TOTP(secret)
                except Exception as e:
                    print(f"Invalid TOTP secret: {e}", file=sys.stderr)
                    return 1

            # Auto-create lockbox if key provided
            auto_key = args.key_id or os.environ.get("GPMASTER_KEY_ID")
            lockbox.add_secret(
                args.name, secret, is_totp=args.totp, auto_create_key=auto_key
            )

        elif args.command == "get":
            secret, is_totp = lockbox.get_secret(args.name)

            if secret is None:
                print(f"Secret not found: {args.name}", file=sys.stderr)
                return 1

            if args.interactive:
                if not TOTP_AVAILABLE:
                    print("Error: pyotp not installed", file=sys.stderr)
                    return 1
                if not is_totp:
                    print(f"Error: {args.name} is not a TOTP secret", file=sys.stderr)
                    return 1

                # Create a temporary lockbox dict with just this secret
                temp_secrets = {args.name: secret}
                old_dump = lockbox.dump_secrets
                lockbox.dump_secrets = lambda: temp_secrets
                interactive_totp_viewer(lockbox, args.quiet)
                lockbox.dump_secrets = old_dump
            elif args.totp_code or is_totp:
                if not TOTP_AVAILABLE:
                    print("Error: pyotp not installed", file=sys.stderr)
                    return 1

                try:
                    totp = pyotp.TOTP(secret)
                    code = totp.now()
                    print(code)
                except Exception as e:
                    print(f"Failed to generate TOTP code: {e}", file=sys.stderr)
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
                print(f"Lockbox encrypted with key: {key_id}")
                print(f"\nSecrets ({len(titles)}):")

            for title in titles:
                print(f"  {title}")

            if note_content is not None and not args.quiet:
                print("\nNote:")
                print(note_content)

                if note_signature:
                    data_to_verify = note_content.encode("utf-8")
                    valid, signer_key = lockbox.gpg.verify(
                        data_to_verify, note_signature
                    )
                    if valid:
                        print(f"Note signature valid (signed by: {signer_key})")
                    else:
                        print(f"Note signature INVALID")
                else:
                    print(f"Note present but not signed")

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

        return 0

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        if not args.quiet:
            print(f"Error: {e}", file=sys.stderr)
        else:
            print(str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
