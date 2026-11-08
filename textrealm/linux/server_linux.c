/*
 * server_linux.c - TextRealm game server, Linux implementation.
 *
 * Single-threaded, single-connection-at-a-time TCP server: no fork(), no
 * threads. One client is accepted, handled to completion in this same
 * process, then the loop goes back to accept() for the next one. This is
 * deliberate for teaching: when something crashes (e.g. a planted
 * overflow), it's unambiguously THIS process crashing - there's no child
 * or worker thread to obscure what's happening.
 *
 * All game rules live in game_logic.c; this file only moves bytes
 * between the socket and process_command().
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strncasecmp */
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../common/game_logic.h"

#define DEFAULT_PORT   9999
#define RECV_BUF_SIZE  1024
#define RESPONSE_SIZE  2048

/* Exit code meaning "a client sent a legitimate QUIT". The supervisor
 * (main.c) treats this as a clean shutdown and does not respawn us. */
#define QUIT_EXIT_CODE 218

static int    grave_size = 1500;
static char  *grave_buf  = NULL;
static size_t grave_used = 0;
static int    reaper_has_come = 0; /* already announced? don't spam every line after */

#define GRAVE_WHISPER_FIRST 10
#define GRAVE_WHISPER_STEP  300
static size_t grave_next_whisper = GRAVE_WHISPER_FIRST;

static FILE *g_log_fp = NULL;

static void open_crash_log(void) {
    char exe[4096];
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len <= 0) return;
    exe[len] = '\0';

    char *slash = strrchr(exe, '/');
    if (!slash) return;
    *slash = '\0';                       /* exe = .../textrealm/linux */

    slash = strrchr(exe, '/');
    if (!slash) return;
    *slash = '\0';                       /* exe = .../textrealm */

    char dir[4096 + 16], path[4096 + 64];
    snprintf(dir, sizeof(dir), "%s/game_logs", exe);
    mkdir(dir, 0755); /* ignore EEXIST */
    snprintf(path, sizeof(path), "%s/textrealm.log", dir);

    /* fopen(), not open(): this is the heap allocation we want sitting
     * directly after grave_buf. See the comment above g_log_fp. */
    g_log_fp = fopen(path, "a");
}

/* Minimal log line writer, safe-ish to call from the signal handlers
 * below (see the NOTE above g_log_fp). Mirrors to both the log file and
 * stdout. */
static void log_crash(const char *fmt, ...) {
    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    char line[512];
    int off = snprintf(line, sizeof(line), "[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    off += vsnprintf(line + off, sizeof(line) - (size_t)off, fmt, ap);
    va_end(ap);
    if (off < 0 || (size_t)off >= sizeof(line) - 1) off = sizeof(line) - 2;
    line[off++] = '\n';
    if (g_log_fp) {
        fwrite(line, 1, (size_t)off, g_log_fp);
        fflush(g_log_fp);

        /* Useless on its own - result is discarded - but it's a real
         * fread() call through the same (possibly corrupted) g_log_fp,
         * right next to the fwrite() above. Demo purpose only: once a
         * student has overflowed grave_buf into this FILE structure,
         * this line gives them a read primitive to show off alongside
         * the write primitive the fwrite() already provides. */
        char scratch[16];
        (void)fread(scratch, 1, sizeof(scratch), g_log_fp);
    }
    write(STDOUT_FILENO, line, (size_t)off); /* mirror to stdout */
}

/* Fires on a fatal signal (e.g. SIGSEGV from a planted overflow). Logs
 * which signal, then restores the default handler and re-raises so the
 * process actually terminates the normal (fatal) way afterward - main.c
 * still sees a real signal death via waitpid(). */
static void crash_signal_handler(int sig) {
    log_crash("SERVER CRASH signal=%d (%s) error code=%d",
               sig, strsignal(sig), 128 + sig);
    signal(sig, SIG_DFL);
    raise(sig);
}

/* Ctrl+C - logged as INTERRUPTED and exits with 130, matching the
 * Windows Ctrl+C handler and main.c's own INTERRUPTED wording. */
static void sigint_handler(int sig) {
    (void)sig;
    log_crash("INTERRUPTED server received SIGINT, exiting with code 130");
    _exit(130);
}

/*
 * reaper_whisper()/scramble_terminal() back the grave_buf/g_log_fp demo
 * declared up near the top of this file - see the comments there.
 *
 * Both APPEND (strcat-style, via snprintf + strlen) onto the caller's
 * buf instead of printing directly - that buffer is what actually gets
 * send()'d down the socket to the CLIENT, so the student watching their
 * own terminal sees the reaper closing in, not just whoever is standing
 * at the server's console.
 *
 * Appends ONE warning line for the given used/limit. The caller (see
 * the GRAVE_WHISPER_FIRST/GRAVE_WHISPER_STEP cadence in handle_client)
 * decides WHEN to call this - this function just renders the line.
 */
static void reaper_whisper(size_t used, size_t limit, char *buf, size_t bufsize) {
    size_t remaining = (used >= limit) ? 0 : (limit - used);
    size_t off = strlen(buf);
    if (remaining <= limit / 10)
        snprintf(buf + off, bufsize - off,
                 "\r\n[reaper] ...something is scratching at the heap. %zu bytes sent, %zu until it arrives...\r\n",
                 used, remaining);
    else
        snprintf(buf + off, bufsize - off,
                 "\r\n[reaper] a cold draft crosses the allocation. %zu bytes sent, %zu bytes of room left.\r\n",
                 used, remaining);
}

/* Appends visibly garbled/ANSI-glitched text onto buf. Purely cosmetic
 * escape codes - it does not touch any real memory - but it sells "the
 * heap is corrupted now" to whoever's terminal renders it, without
 * actually taking the server down. */
static void scramble_terminal(char *buf, size_t bufsize) {
    static const char *glitch_words[] = {
        "R3AP3R", "h34p_c0rrupt", "chunk->fd", "chunk->bk",
        "free()?", "0xDEADC0DE", "who.is.next", "ask_malloc_nicely"
    };
    size_t off = strlen(buf);
    off += (size_t)snprintf(buf + off, bufsize - off, "\033[1;31m");
    for (int i = 0; i < 6 && off < bufsize; i++) {
        int fg = 30 + (rand() % 8);
        int bg = 40 + (rand() % 8);
        off += (size_t)snprintf(buf + off, bufsize - off, "\033[%d;%dm %s \033[0m",
               fg, bg, glitch_words[rand() % (int)(sizeof(glitch_words) / sizeof(glitch_words[0]))]);
    }
    snprintf(buf + off, bufsize - off, "\033[0m\r\n");
}

/* Returns 1 if the client asked to QUIT, 0 if it just disconnected. */
static int handle_client(int client_fd) {
    int quit_seen = 0;
    Character ch;
    character_init(&ch);

    char recv_buf[RECV_BUF_SIZE];

    /* grave_buf itself is allocated once, in main(), before the crash
     * log is opened - so it stays adjacent to g_log_fp's FILE struct on
     * the heap for the lifetime of the process. Just reset the demo's
     * per-connection state here. */
    grave_used = 0;
    reaper_has_come = 0;
    grave_next_whisper = GRAVE_WHISPER_FIRST;
    if (grave_buf) memset(grave_buf, 0, (size_t)grave_size);

    static const char banner[] =
        "============================================\r\n"
        " Welcome to TextRealm - A Text Adventure!\r\n"
        " Type HELP for a list of commands.\r\n"
        "============================================\r\n> ";
    send(client_fd, banner, sizeof(banner) - 1, 0);

    for (;;) {
        ssize_t n = recv(client_fd, recv_buf, sizeof(recv_buf) - 1, 0);
        if (n <= 0) break; /* client closed, or error */
        recv_buf[n] = '\0';

        /* Strip the line terminator, then hand the whole input to the
         * game logic in one call. */
        while (n > 0 && (recv_buf[n - 1] == '\n' || recv_buf[n - 1] == '\r'))
            recv_buf[--n] = '\0';

        /* --- heap overflow demo: copy raw input into grave_buf ---------
         * No check that grave_used + n <= grave_size before the memcpy.
         * Once a client has pushed grave_size bytes through, every byte
         * after that is written past the end of the malloc(grave_size)
         * allocation - straight into whatever the allocator placed next
         * on the heap. */
        char reaper_msg[512];
        reaper_msg[0] = '\0';

        if (grave_buf && n > 0) {
            memcpy(grave_buf + grave_used, recv_buf, (size_t)n);
            grave_used += (size_t)n;

            /* First warning once GRAVE_WHISPER_FIRST (10) bytes total
             * have gone through, then again every GRAVE_WHISPER_STEP
             * (300) bytes after that - a fixed cadence, not a fraction
             * of grave_size, and tracked by cumulative grave_used, not
             * the size of any one message. If one send jumps past
             * several thresholds at once, this fires once per threshold
             * crossed so nothing gets skipped. */
            while (!reaper_has_come &&
                   grave_next_whisper < (size_t)grave_size &&
                   grave_used >= grave_next_whisper) {
                reaper_whisper(grave_used, (size_t)grave_size, reaper_msg, sizeof(reaper_msg));
                grave_next_whisper += GRAVE_WHISPER_STEP;
            }

            if (grave_used >= (size_t)grave_size) {
                if (!reaper_has_come) {
                    size_t off = strlen(reaper_msg);
                    snprintf(reaper_msg + off, sizeof(reaper_msg) - off, "\r\nTHE REAPER HAS COME\r\n");
                    reaper_has_come = 1;
                }
                scramble_terminal(reaper_msg, sizeof(reaper_msg));
            }
        }

        /* Send straight to the CLIENT - this is what the student watching
         * their own terminal is meant to see - and mirror it to the
         * server's console too, so whoever's running the server sees it
         * happen in real time as well. */
        if (reaper_msg[0]) {
            printf("%s", reaper_msg);
            fflush(stdout);
            send(client_fd, reaper_msg, strlen(reaper_msg), 0);
        }

        char response[RESPONSE_SIZE];
        int rc = process_command(&ch, recv_buf, response, sizeof(response));
        if (rc == -1) { quit_seen = 1; break; }

        strncat(response, "\r\n> ", sizeof(response) - strlen(response) - 1);
        send(client_fd, response, strlen(response), 0);
    }

    close(client_fd);
    return quit_seen;
}

int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    if (argc > 1) port = atoi(argv[1]);

    /* Allocate the demo heap buffer FIRST - open_crash_log() below does
     * the only other heap allocation before the accept() loop starts
     * (fopen()'s FILE struct), so it lands in the chunk right after this
     * one. Don't insert any other malloc()/fopen()/strdup() etc. between
     * these two calls, or that adjacency breaks. */
    grave_buf = malloc((size_t)grave_size);
    if (grave_buf) memset(grave_buf, 0, (size_t)grave_size);

    open_crash_log();

    signal(SIGINT, sigint_handler);
    signal(SIGSEGV, crash_signal_handler);
    signal(SIGBUS,  crash_signal_handler);
    signal(SIGILL,  crash_signal_handler);
    signal(SIGFPE,  crash_signal_handler);
    signal(SIGABRT, crash_signal_handler);

    srand((unsigned int)time(NULL));

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((unsigned short)port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }
    if (listen(server_fd, 16) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("TextRealm game server listening on port %d (Linux, single-connection)\n", port);

    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) { perror("accept"); continue; }

        printf("Connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        /* Handled right here, in this same process - no fork, no thread.
         * Only one client can be connected at a time by design. */
        int quit = handle_client(client_fd);
        if (quit) {
            close(server_fd);
            exit(QUIT_EXIT_CODE);
        }
    }

    close(server_fd);
    return 0;
}
