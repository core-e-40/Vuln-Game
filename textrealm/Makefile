# TextRealm top-level Makefile
#
# TEACHING BUILD: every binary this produces is deliberately UNMITIGATED.
# Stack canaries, glibc fortify, PIE/ASLR and (on Windows) DEP/ASLR are all
# turned off on both platforms, so a planted buffer overflow corrupts
# memory/crashes for real instead of being caught by a mitigation and
# reported as "*** buffer overflow detected ***" / "*** stack smashing
# detected ***". There is only one build mode — plain `make` always
# produces the vulnerable binaries, on both platforms, so there's no
# hardened/vulnerable mismatch to mix up.
#
# Builds:
#   linux/textrealm_server          Linux server        (gcc,   unmitigated)
#   windows/textrealm_server.exe    Windows server       (MinGW, unmitigated)
#   textrealm.com                   Cosmopolitan supervisor (cosmocc, main.c)
#
# Usage:
#   make                build everything (linux, windows [64-bit], supervisor)
#   make linux          Linux server only
#   make windows        Windows server only (64-bit)
#   make windows32      Windows server, 32-bit (i686) - opt-in, not part of
#                       `all`. Same source as windows/textrealm_server.exe,
#                       but on i686 the SEH chain this plants (via __try1/
#                       __except1 around the strcpy in handle_client) lives
#                       on the stack and is reachable by the overflow, which
#                       is what makes the classic "pop pop ret" SEH-overwrite
#                       technique demonstrable - on x86_64 the same code
#                       builds, but SEH there is table-based, not
#                       stack-resident, so the exploit doesn't apply.
#   make supervisor     Cosmopolitan supervisor only
#   make clean          remove built binaries
#
# Override tools if they are not on PATH, e.g.:
#   make COSMOCC=$HOME/cosmocc/bin/cosmocc WIN_CC=i686-w64-mingw32-gcc

COMMON_SRC = common/game_logic.c
COMMON_HDR = common/game_logic.h

# --- Shared "no mitigations" flags -----------------------------------------
# -O0                    don't let the optimizer rearrange/eliminate the bug
# -g                     keep symbols/line info for stepping through crashes
# -fno-stack-protector   no stack canary
# -U_FORTIFY_SOURCE      no glibc _chk() overflow checks (no-op on Windows,
#                        harmless to pass)
UNSAFE_FLAGS = -g -O0 -std=c11 -fno-stack-protector -U_FORTIFY_SOURCE

# --- Linux server ---
LINUX_CC    ?= gcc
# -no-pie            fixed, predictable load address (no ASLR on the binary)
# -Wl,-z,execstack   executable stack (no NX), consistent with "no mitigations"
LINUX_FLAGS = -Wall -Wextra $(UNSAFE_FLAGS) -no-pie -Wl,-z,execstack
LINUX_SRC   = linux/server_linux.c $(COMMON_SRC)
LINUX_BIN   = linux/textrealm_server

# --- Windows server (MinGW-w64 cross-compile) ---
WIN_CC      ?= x86_64-w64-mingw32-gcc
# --dynamicbase:no / --nxcompat:no = ASLR off / DEP off, mirroring the Linux
# flags above so both platforms are equally unmitigated.
# -std=gnu11 (not plain -std=c11, which UNSAFE_FLAGS sets): MinGW's
# __except1 macro (<excpt.h>) uses the bare `asm` keyword, which strict
# ISO C11 disables - GNU C11 keeps it. The later -std wins, overriding
# UNSAFE_FLAGS's -std=c11.
WIN_FLAGS   = -Wall $(UNSAFE_FLAGS) -std=gnu11 -Wl,--disable-dynamicbase -Wl,--disable-nxcompat
WIN_LIBS    = -lws2_32
WIN_SRC     = windows/server_windows.c $(COMMON_SRC)
WIN_BIN     = windows/textrealm_server.exe

# --- Windows server, 32-bit (i686) - for the SEH-overwrite demo above ---
WIN32_CC    ?= i686-w64-mingw32-gcc
WIN32_FLAGS = -Wall $(UNSAFE_FLAGS) -std=gnu11 -Wl,--disable-dynamicbase -Wl,--disable-nxcompat
WIN32_BIN   = windows/textrealm_server32.exe

# --- Cosmopolitan supervisor (see header comment of main.c) ---
# Not part of the vulnerable surface (it only spawns/logs); built normally.
COSMOCC     ?= $(firstword $(wildcard $(HOME)/cosmocc/bin/cosmocc) cosmocc)
COSMO_FLAGS = -O2
SUP_SRC     = main.c
SUP_BIN     = textrealm.com
# cosmocc also emits these next to the .com
SUP_EXTRA   = $(SUP_BIN).dbg $(basename $(SUP_BIN)).aarch64.elf

# 'all' skips the Windows build (with a notice) if MinGW-w64 isn't installed,
# so the Linux server and supervisor still build.
HAVE_WIN_CC := $(shell command -v $(WIN_CC) 2>/dev/null)
ifeq ($(HAVE_WIN_CC),)
ALL_TARGETS = linux supervisor
else
ALL_TARGETS = linux windows supervisor
endif

all: $(ALL_TARGETS)
	@$(if $(HAVE_WIN_CC),,echo "NOTE: $(WIN_CC) not found - skipped Windows build (sudo apt install gcc-mingw-w64-x86-64)")

linux: $(LINUX_BIN)
windows: $(WIN_BIN)
windows32: $(WIN32_BIN)
supervisor: $(SUP_BIN)

$(LINUX_BIN): $(LINUX_SRC) $(COMMON_HDR)
	$(LINUX_CC) $(LINUX_FLAGS) -o $@ $(LINUX_SRC)

$(WIN_BIN): $(WIN_SRC) $(COMMON_HDR)
	@command -v $(WIN_CC) >/dev/null || { echo "error: $(WIN_CC) not found; install MinGW-w64 (sudo apt install gcc-mingw-w64-x86-64) or set WIN_CC="; exit 1; }
	$(WIN_CC) $(WIN_FLAGS) -o $@ $(WIN_SRC) $(WIN_LIBS)

$(WIN32_BIN): $(WIN_SRC) $(COMMON_HDR)
	@command -v $(WIN32_CC) >/dev/null || { echo "error: $(WIN32_CC) not found; install 32-bit MinGW-w64 (sudo apt install gcc-mingw-w64-i686) or set WIN32_CC="; exit 1; }
	$(WIN32_CC) $(WIN32_FLAGS) -o $@ $(WIN_SRC) $(WIN_LIBS)

$(SUP_BIN): $(SUP_SRC)
	$(COSMOCC) $(COSMO_FLAGS) -o $@ $(SUP_SRC)

clean:
	rm -f $(LINUX_BIN) $(WIN_BIN) $(WIN32_BIN) $(SUP_BIN) $(SUP_EXTRA)

.PHONY: all linux windows windows32 supervisor clean
