/*
 * server_windows.c - TextRealm game server, Windows implementation.
 *
 * Single-threaded, single-connection-at-a-time TCP server: no
 * CreateThread() per connection. One client is accepted, handled to
 * completion in this same thread, then the loop goes back to accept()
 * for the next one. This is deliberate for teaching: when something
 * crashes (e.g. a planted overflow), it's unambiguously THIS process
 * crashing - there's no worker thread to obscure what's happening.
 *
 * All game rules live in game_logic.c; this file only moves bytes
 * between the socket and process_command().
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include <excpt.h>

#include "../common/game_logic.h"

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT   9999
#define RECV_BUF_SIZE  1024
#define RESPONSE_SIZE  2048

/* Exit code meaning "a client sent a legitimate QUIT". The supervisor
 * (main.c) treats this as a clean shutdown and does not respawn us. */
#define QUIT_EXIT_CODE 218

/*
 * Crash/interrupt logging, mirroring linux/server_linux.c. There's only
 * ever one thread handling clients here, so a crash while handling one
 * takes the whole process down - main.c's own CRASH logging (waiting on
 * this process) already sees that happen. This adds a second, more
 * specific log line - which exception - written directly into the same
 * game_logs\textrealm.log file, computed relative to this binary's own
 * path (textrealm\windows\textrealm_server.exe ->
 * textrealm\game_logs\textrealm.log) - before the process goes down.
 */
static FILE *g_log = NULL;

static void open_crash_log(void) {
    char exe[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, exe, sizeof(exe));
    if (n == 0 || n >= sizeof(exe)) return;

    char *slash = strrchr(exe, '\\');
    if (!slash) slash = strrchr(exe, '/');
    if (!slash) return;
    *slash = '\0';                       /* exe = ...\textrealm\windows */

    slash = strrchr(exe, '\\');
    if (!slash) slash = strrchr(exe, '/');
    if (!slash) return;
    *slash = '\0';                       /* exe = ...\textrealm */

    char dir[MAX_PATH + 16], path[MAX_PATH + 64];
    snprintf(dir, sizeof(dir), "%s\\game_logs", exe);
    CreateDirectoryA(dir, NULL); /* ignore error if it already exists */
    snprintf(path, sizeof(path), "%s\\textrealm.log", dir);

    g_log = fopen(path, "a");
}

static void log_crash(const char *fmt, ...) {
    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_s(&tm, &now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    if (g_log) {
        fprintf(g_log, "[%s] ", ts);
        va_list ap;
        va_start(ap, fmt);
        vfprintf(g_log, fmt, ap);
        va_end(ap);
        fputc('\n', g_log);
        fflush(g_log);
    }

    /* Mirror to stdout */
    fprintf(stdout, "[%s] ", ts);
    va_list ap2;
    va_start(ap2, fmt);
    vfprintf(stdout, fmt, ap2);
    va_end(ap2);
    fputc('\n', stdout);
    fflush(stdout);
}

/* Called by Windows on an unhandled exception (e.g. an access violation
 * from a planted overflow) before it terminates the process - logs which
 * exception, then lets the normal (fatal) termination proceed. */
static LONG WINAPI crash_filter(EXCEPTION_POINTERS *info) {
    log_crash("SERVER CRASH exception=0x%08lX at address=%p",
               (unsigned long)info->ExceptionRecord->ExceptionCode,
               info->ExceptionRecord->ExceptionAddress);
    return EXCEPTION_EXECUTE_HANDLER;
}

/* Ctrl+C / Ctrl+Break on the console - the Windows equivalent of SIGINT.
 * Logged as INTERRUPTED and exits with 130 so it reads the same way in
 * the log as a Linux SIGINT death does. */
static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
        log_crash("INTERRUPTED server received Ctrl+C/Break, exiting with code 130");
        ExitProcess(130);
    }
    return FALSE;
}

/*
 * Low-level SEH frame, installed around the vulnerable strcpy below via
 * __try1()/__except1 (from MinGW's <excpt.h>). This is NOT the same as
 * MSVC/clang's __try/__except keywords - GCC doesn't implement those at
 * all. __try1(handler) is an inline-asm macro that, on 32-bit (i686),
 * pushes a real EXCEPTION_REGISTRATION record onto the stack and links
 * it into the thread's SEH chain via fs:[0]:
 *
 *     struct _EXCEPTION_REGISTRATION {
 *         struct _EXCEPTION_REGISTRATION *prev;
 *         EXCEPTION_DISPOSITION (*handler)(...);  <-- the pop-pop-ret target
 *     };
 *
 * That handler function pointer is exactly what the classic SEH-overwrite
 * exploit clobbers with a planted overflow, then redirects through a
 * "pop pop ret" gadget to land back on the stack. __except1 just pops
 * this record back off when the protected block finishes normally.
 *
 * On x86_64 the SAME macro instead emits a static table entry (the
 * .seh_handler/.seh_handlerdata directives) - nothing is pushed onto the
 * stack at runtime, so there's no handler pointer there to overwrite.
 * The classic SEH-chain-overwrite technique is an x86-only exploit for
 * exactly this reason; build the 32-bit target (`make windows32`, using
 * i686-w64-mingw32-gcc) to demonstrate it.
 */
/* __attribute__((used)): referenced only via inline-asm .rva text in the
 * __try1() macro (see below), so GCC's normal usage analysis can't see
 * it and would otherwise warn "defined but not used". */
static EXCEPTION_DISPOSITION __attribute__((used)) easter_egg_seh_handler(
        struct _EXCEPTION_RECORD *rec, void *frame,
        struct _CONTEXT *ctx, void *dispatch) {
    (void)frame; (void)ctx; (void)dispatch;
    log_crash("SEH HANDLER INVOKED exception=0x%08lX at address=%p",
               (unsigned long)rec->ExceptionCode, rec->ExceptionAddress);
    return ExceptionContinueSearch;
}

/* Returns 1 if the client asked to QUIT, 0 if it just disconnected. */
static int handle_client(SOCKET client_sock) {
    int quit_seen = 0;
    Character ch;
    character_init(&ch);

    char recv_buf[RECV_BUF_SIZE];

    static const char banner[] =
        "============================================\r\n"
        " Welcome to TextRealm - A Text Adventure!\r\n"
        " Type HELP for a list of commands.\r\n"
        "============================================\r\n> ";
    send(client_sock, banner, (int)(sizeof(banner) - 1), 0);

    for (;;) {
        int n = recv(client_sock, recv_buf, (int)sizeof(recv_buf) - 1, 0);
        if (n <= 0) break; /* client closed, or error */
        recv_buf[n] = '\0';

        /* Strip the line terminator, then hand the whole input to the
         * game logic in one call. */
        while (n > 0 && (recv_buf[n - 1] == '\n' || recv_buf[n - 1] == '\r'))
            recv_buf[--n] = '\0';

        char response[RESPONSE_SIZE];
        int rc = process_command(&ch, recv_buf, response, sizeof(response));

        __try1(easter_egg_seh_handler);
        {
            /* Deliberately vulnerable: response can be up to RESPONSE_SIZE
             * (2048) bytes, but recv_buf is only RECV_BUF_SIZE (1024) -
             * strcpy doesn't check that, so a long enough response
             * overflows recv_buf's stack frame - and, on the 32-bit
             * build, the SEH registration record __try1 just pushed. */
            strcpy(recv_buf, response);

            if (strcmp(recv_buf, "EASTER_EGG") == 0) {
                static const char secret[] = "You found the easter egg!\r\n";
                send(client_sock, secret, (int)(sizeof(secret) - 1), 0);
            }
        }
        __except1;

        if (rc == -1) { quit_seen = 1; break; }

        strncat(response, "\r\n> ", sizeof(response) - strlen(response) - 1);
        send(client_sock, response, (int)strlen(response), 0);
    }

    closesocket(client_sock);
    return quit_seen;
}

int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    if (argc > 1) port = atoi(argv[1]);

    open_crash_log();
    SetUnhandledExceptionFilter(crash_filter);
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    srand((unsigned int)time(NULL));

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    SOCKET server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock == INVALID_SOCKET) {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    BOOL opt = TRUE;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((unsigned short)port);

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }
    if (listen(server_sock, 16) == SOCKET_ERROR) {
        fprintf(stderr, "listen failed: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    printf("TextRealm game server listening on port %d (Windows, single-connection)\n", port);

    for (;;) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        SOCKET client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock == INVALID_SOCKET) {
            fprintf(stderr, "accept failed: %d\n", WSAGetLastError());
            continue;
        }

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
        printf("Connection from %s:%d\n", ip_str, ntohs(client_addr.sin_port));

        /* Handled right here, on this same thread - no CreateThread().
         * Only one client can be connected at a time by design. */
        int quit = handle_client(client_sock);
        if (quit) {
            closesocket(server_sock);
            WSACleanup();
            ExitProcess(QUIT_EXIT_CODE);
        }
    }

    closesocket(server_sock);
    WSACleanup();
    return 0;
}
