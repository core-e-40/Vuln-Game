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

/*
 * Crash/interrupt logging, mirroring windows/server_windows.c. There's
 * only ever one process here, so a crash while handling a client takes
 * the whole server down - main.c's own CRASH logging (waiting on this
 * process) already sees that happen. This adds a second, more specific
 * log line - which signal - written directly into the same
 * game_logs/textrealm.log file main.c uses, computed relative to this
 * binary's own path (textrealm/linux/textrealm_server ->
 * textrealm/game_logs/textrealm.log) - before the process goes down.
 *
 * NOTE: for simplicity this uses snprintf()/write() from a signal
 * handler, which is not strictly POSIX async-signal-safe (snprintf isn't
 * on the safe list). That's an acceptable tradeoff for a teaching
 * server; don't copy this pattern into production code.
 */
static int g_log_fd = -1;

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

    g_log_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

/* Minimal, allocation-light log line writer, safe to call from the
 * signal handlers below. Mirrors to both the log file and stdout. */
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
    if (g_log_fd >= 0) write(g_log_fd, line, (size_t)off);
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

/* Returns 1 if the client asked to QUIT, 0 if it just disconnected. */
static int handle_client(int client_fd) {
    int quit_seen = 0;
    Character ch;
    character_init(&ch);

    char recv_buf[RECV_BUF_SIZE];

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
