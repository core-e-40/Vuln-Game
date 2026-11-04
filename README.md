# TextRealm — TCP Text Adventure Game Server

A simple line-oriented TCP game server. A client connects, sends text
commands terminated by `\r\n` (or `\n`), and gets a text response back.
Players create a character, check their status, fight enemies, manage
an inventory, and buy items from a shop.

## Building

Everything is built from the single top-level `Makefile`, from inside
`textrealm/`:

```sh
cd textrealm
make clean
make
```

`make clean` removes any previously built binaries first, so a rebuild
after pulling changes (or switching toolchains) always starts from a
known-clean state rather than mixing old and new object/binary files.
`make` then builds:

- `linux/textrealm_server` — the Linux server (always built; needs `gcc`).
- `windows/textrealm_server.exe` — the 64-bit Windows server, cross-compiled
  with MinGW-w64. Skipped with a notice if `x86_64-w64-mingw32-gcc` isn't
  found.
- `textrealm.com` — the Cosmopolitan supervisor (`main.c`). Spawns and
  respawns the platform server, and logs every start/crash/interrupt to
  `game_logs/textrealm.log`.

Run the whole stack through the supervisor:

```sh
./textrealm.com                # spawns linux/textrealm_server or
                                # windows/textrealm_server.exe, port 9999
```

Or run a server binary directly (bypassing the supervisor, e.g. to point
at a specific build):

```sh
./linux/textrealm_server 12345          # custom port
./windows/textrealm_server.exe 12345
```

### Other Makefile targets

```sh
make linux          # linux/textrealm_server only
make windows         # windows/textrealm_server.exe only (64-bit)
make windows32       # windows/textrealm_server32.exe (32-bit, i686) - opt-in,
                      # not built by `make`/`make windows`. Needed for the
                      # classic SEH-overwrite ("pop pop ret") exercise: the
                      # SEH chain __try1/__except1 install in
                      # server_windows.c lives on the stack only on 32-bit
                      # builds; on 64-bit it's a static table entry instead.
make supervisor       # textrealm.com only
```

**Every binary this Makefile produces is deliberately unmitigated** for
teaching purposes: no stack canary, no glibc fortify, no PIE/ASLR, and
(on Windows) no DEP/ASLR either. A planted overflow crashes for real
instead of being caught and reported by a mitigation. There is only one
build mode — plain `make` always produces these unmitigated binaries, on
every platform, so there's no hardened/vulnerable version to mix up.

## Dependencies

| Tool | Used for | Required? |
|---|---|---|
| `gcc` + `make` | Linux server (`linux/textrealm_server`) | Yes |
| `gcc-mingw-w64-x86-64` (provides `x86_64-w64-mingw32-gcc`) | 64-bit Windows server (`windows/textrealm_server.exe`) | Only for `make` / `make windows` — skipped with a notice if missing |
| `gcc-mingw-w64-i686` (provides `i686-w64-mingw32-gcc`) | 32-bit Windows server (`windows/textrealm_server32.exe`, the SEH demo build) | Only for `make windows32` |
| [Cosmopolitan](https://github.com/jart/cosmopolitan) `cosmocc` | Supervisor (`textrealm.com`, from `main.c`) | Only for `make` / `make supervisor` |

On Debian/Ubuntu, install the MinGW cross-compilers with:

```sh
sudo apt-get install gcc-mingw-w64-x86-64 gcc-mingw-w64-i686
```

`cosmocc` is not packaged by distros; install it per the
[Cosmopolitan project's instructions](https://github.com/jart/cosmopolitan).
The Makefile looks for it at `$HOME/cosmocc/bin/cosmocc` first, falling
back to `cosmocc` on `PATH`; override with `make COSMOCC=/path/to/cosmocc`.

Any of these tools can be pointed elsewhere without editing the
Makefile, e.g.:

```sh
make WIN_CC=x86_64-w64-mingw32-gcc WIN32_CC=i686-w64-mingw32-gcc COSMOCC=$HOME/cosmocc/bin/cosmocc
```

## Project layout

```
textrealm/
├── Makefile              # top-level build: linux, windows, windows32, supervisor
├── main.c                # Cosmopolitan supervisor (spawns/respawns/logs the server)
├── common/
│   ├── game_logic.h      # shared data structures / API
│   └── game_logic.c      # all game rules — platform independent
├── linux/
│   └── server_linux.c    # POSIX sockets, single-connection-at-a-time
├── windows/
│   └── server_windows.c  # Winsock2, single-connection-at-a-time
├── game_logs/            # textrealm.log (crash/interrupt log, gitignored)
└── README.md

# produced by `make` (not checked in except windows/textrealm_server.exe):
#   linux/textrealm_server
#   windows/textrealm_server.exe       (64-bit)
#   windows/textrealm_server32.exe     (32-bit, from `make windows32` only)
#   textrealm.com(.dbg) / textrealm.aarch64.elf
```

The two platform files (`server_linux.c`, `server_windows.c`) only
handle sockets and feed each line of client input into
`process_command()` in `common/game_logic.c`. Both are intentionally
single-threaded and single-connection-at-a-time (no `fork()`, no
`CreateThread()`) — only one client can be connected at a time, by
design, so that a crash is unambiguously the server process itself
crashing, not a child or worker thread.

## Protocol — formal syntax

Commands are ASCII text, one per line, case-insensitive, terminated by
`CRLF` (`\r\n`) — a bare `\n` is also accepted. Tokens are separated by
single spaces. In ABNF-style notation:

```
line        = command CRLF

command     = help / create / status / attack / inventory / buy / quit

help        = "HELP"
create      = "CREATE" SP name SP class
status      = "STATUS"
attack      = "ATTACK" SP enemy
inventory   = "INVENTORY"
buy         = "BUY" SP item
quit        = "QUIT"

name        = 1*32ALPHA
class       = "WARRIOR" / "MAGE" / "ROGUE"
enemy       = "GOBLIN" / "SLIME" / "ORC" / "DRAGON"
item        = "POTION" / "SHIELD" / "SWORD" / "BOW"

SP          = %x20                  ; single space
CRLF        = %x0D.0A / %x0A        ; CR LF, or bare LF
ALPHA       = %x41-5A / %x61-7A     ; A-Z / a-z
```

A session must `CREATE` a character before using `STATUS`, `ATTACK`,
`INVENTORY`, or `BUY`. `HELP` and `QUIT` work at any time.

### Command reference

| Command                  | Effect                                                             |
|---------------------------|---------------------------------------------------------------------|
| `HELP`                    | Prints the command list and syntax.                                |
| `CREATE <name> <class>`   | Creates a character. Class sets starting HP: WARRIOR 120, ROGUE 100, MAGE 80. Starting gold: 50. |
| `STATUS`                  | Shows name, class, level, HP, gold, XP.                            |
| `ATTACK <enemy>`          | Fights the named enemy to a conclusion (win: gold/XP, possible level-up; lose: HP drops to 1, lose 25% gold). |
| `INVENTORY`               | Lists carried items (max 10).                                      |
| `BUY <item>`              | Buys an item from the shop if you have enough gold and room.       |
| `QUIT`                    | Server says goodbye and closes the connection.                     |

## Trying it out

Connect with any raw TCP client, e.g. `nc 127.0.0.1 9999` or
`telnet 127.0.0.1 9999`, then:

```
HELP
CREATE Thorin WARRIOR
STATUS
BUY SWORD
INVENTORY
ATTACK GOBLIN
STATUS
QUIT
```

## Notes

- Each connection has its own independent, in-memory character; nothing
  is persisted to disk. Only one connection is handled at a time (see
  Project layout above) — a second client has to wait for the first to
  disconnect.
- Both platform servers call into the exact same `game_logic.c`, so
  game behavior is consistent across platforms.
- **This is a deliberately vulnerable teaching build, not a hardened
  reference implementation.** Known planted issues include an unbounded
  `strcpy()` in `process_command()` (`common/game_logic.c`) and another
  in `handle_client()` (`windows/server_windows.c`). All builds disable
  the usual mitigations (stack canary, glibc fortify, PIE/ASLR, DEP) — see
  Building above — so these overflows crash for real.
- Crashes and interrupts (Ctrl+C) are logged to `game_logs/textrealm.log`
  and mirrored to stdout, both by the supervisor (`main.c`) and by the
  server binaries themselves.
