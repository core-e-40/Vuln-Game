/*
 * TextRealm - Windows 32-bit Server
 *
 * Commands:
 *   HELP, CREATE, STATUS, etc. - normal gameplay
 *   ECHO                       - existing simple overflow
 *   BIO <text>                 - save character biography
 *   BIO SHOW                   - display biography
 *   SEHTEST                    - vectored exception test
 *   SEHFRAME                   - stack SEH diagnostic
 *   SEHFRAME DEMO              - controlled SEH modification
 *
 * Educational lab implementation.
 */

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <excpt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <stdint.h>

#include "../common/game_logic.h"

#define DEFAULT_PORT 9999
#define RECV_BUF_SIZE 1024
#define RESPONSE_SIZE 2048
#define QUIT_EXIT_CODE 218
#define BIO_SIZE 128

static FILE *g_log = NULL;
static PVOID g_exception_handler = NULL;
static volatile LONG g_seh_test_seen = 0;

/* ============================================
   CRASH LOGGING
   ============================================ */

static void open_crash_log(void)
{
    char exe[MAX_PATH];

    DWORD n = GetModuleFileNameA(
        NULL, exe, sizeof(exe)
    );

    if (n == 0 || n >= sizeof(exe))
        return;

    char *slash = strrchr(exe, '\\');

    if (!slash)
        slash = strrchr(exe, '/');

    if (!slash)
        return;

    *slash = '\0';

    slash = strrchr(exe, '\\');

    if (!slash)
        slash = strrchr(exe, '/');

    if (!slash)
        return;

    *slash = '\0';

    char dir[MAX_PATH + 16];
    char path[MAX_PATH + 64];

    snprintf(
        dir, sizeof(dir),
        "%s\\game_logs", exe
    );

    CreateDirectoryA(dir, NULL);

    snprintf(
        path, sizeof(path),
        "%s\\textrealm.log", dir
    );

    g_log = fopen(path, "a");
}

static void log_crash(const char *fmt, ...)
{
    char ts[32];

    time_t now = time(NULL);
    struct tm tm;

    localtime_s(&tm, &now);

    strftime(
        ts, sizeof(ts),
        "%Y-%m-%d %H:%M:%S",
        &tm
    );

    va_list ap;

    va_start(ap, fmt);

    if (g_log) {
        fprintf(g_log, "[%s] ", ts);
        vfprintf(g_log, fmt, ap);
        fputc('\n', g_log);
        fflush(g_log);
    }

    va_end(ap);

    va_start(ap, fmt);

    fprintf(stdout, "[%s] ", ts);
    vfprintf(stdout, fmt, ap);
    fputc('\n', stdout);
    fflush(stdout);

    va_end(ap);
}

static LONG WINAPI crash_filter(
    EXCEPTION_POINTERS *info
)
{
    log_crash(
        "SERVER CRASH exception=0x%08lX at address=%p",
        (unsigned long)
            info->ExceptionRecord->ExceptionCode,
        info->ExceptionRecord->ExceptionAddress
    );

    return EXCEPTION_EXECUTE_HANDLER;
}

static BOOL WINAPI console_ctrl_handler(
    DWORD ctrl_type
)
{
    if (ctrl_type == CTRL_C_EVENT ||
        ctrl_type == CTRL_BREAK_EVENT) {

        log_crash(
            "INTERRUPTED server received Ctrl+C/Break"
        );

        ExitProcess(130);
    }

    return FALSE;
}

/* ============================================
   VECTORED EXCEPTION DIAGNOSTIC
   ============================================ */

static LONG CALLBACK textrealm_exception_handler(
    PEXCEPTION_POINTERS info
)
{
    DWORD code =
        info->ExceptionRecord->ExceptionCode;

    if (code == 0xE0424242UL) {
        InterlockedExchange(
            &g_seh_test_seen, 1
        );

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static void register_exception_handler(void)
{
    g_exception_handler =
        AddVectoredExceptionHandler(
            1,
            textrealm_exception_handler
        );

    if (g_exception_handler != NULL) {
        printf(
            "[+] Vectored exception handler registered\n"
        );
    } else {
        printf(
            "[-] Vectored exception handler registration failed\n"
        );
    }
}

static void test_exception_handler(
    char *response,
    size_t response_size
)
{
    if (g_exception_handler == NULL) {
        snprintf(
            response,
            response_size,
            "SEH diagnostic unavailable"
        );
        return;
    }

    InterlockedExchange(&g_seh_test_seen, 0);

    RaiseException(
        0xE0424242UL,
        0,
        0,
        NULL
    );

    snprintf(
        response,
        response_size,
        "%s",
        g_seh_test_seen
            ? "SEH diagnostic passed: handler invoked"
            : "SEH diagnostic failed"
    );
}

/* ============================================
   STACK-BASED SEH SUPPORT
   ============================================ */

#if defined(__i386__)

typedef struct TextRealmSEHRegistration {
    struct TextRealmSEHRegistration *previous;
    void *handler;
} TextRealmSEHRegistration;

static EXCEPTION_DISPOSITION
seh_frame_handler(
    struct _EXCEPTION_RECORD *record,
    void *frame,
    struct _CONTEXT *context,
    void *dispatcher
)
{
    (void)frame;
    (void)context;
    (void)dispatcher;

    log_crash(
        "STACK SEH HANDLER INVOKED exception=0x%08lX",
        (unsigned long)record->ExceptionCode
    );

    return ExceptionContinueSearch;
}

#define INSTALL_SEH(reg)                       \
    do {                                       \
        __asm__ __volatile__(                  \
            "movl %%fs:0, %%eax\n\t"           \
            "movl %%eax, %0"                   \
            : "=m"((reg).previous)             \
            :                                  \
            : "eax", "memory"                   \
        );                                     \
        (reg).handler =                        \
            (void *)seh_frame_handler;         \
        __asm__ __volatile__(                  \
            "leal %0, %%eax\n\t"                \
            "movl %%eax, %%fs:0"               \
            :                                  \
            : "m"(reg)                         \
            : "eax", "memory"                   \
        );                                     \
    } while (0)

#define RESTORE_SEH(reg)                       \
    do {                                       \
        __asm__ __volatile__(                  \
            "movl %0, %%eax\n\t"                \
            "movl %%eax, %%fs:0"               \
            :                                  \
            : "m"((reg).previous)              \
            : "eax", "memory"                   \
        );                                     \
    } while (0)

/* ============================================
   SEHFRAME DIAGNOSTIC
   ============================================ */

__attribute__((noinline))
static void test_stack_seh_frame(
    const char *input,
    char *response,
    size_t response_size
)
{
    volatile TextRealmSEHRegistration registration;
    char seh_input[128];

    memset(seh_input, 0, sizeof(seh_input));

    snprintf(
        seh_input,
        sizeof(seh_input),
        "%s",
        input
    );

    INSTALL_SEH(registration);

    printf("\n========== SEHFRAME ==========\n");
    printf("[SEHFRAME] Buffer address: %p\n", (void *)seh_input);
    printf("[SEHFRAME] Buffer size: %u\n", (unsigned int)sizeof(seh_input));
    printf("[SEHFRAME] Registration address: %p\n", (void *)&registration);
    printf("[SEHFRAME] Handler address: %p\n", (void *)seh_frame_handler);
    fflush(stdout);

    if (strcmp(input, "DEMO") == 0) {
        void *original_handler = registration.handler;
        registration.handler = (void *)(uintptr_t)0x41414141;
        Sleep(2000);
        registration.handler = original_handler;
    }

    Sleep(1000);
    RESTORE_SEH(registration);

    snprintf(
        response,
        response_size,
        "SEHFRAME completed: buffer=%p registration=%p",
        (void *)seh_input,
        (void *)&registration
    );
}

/* ============================================
   BIO - CHARACTER BIOGRAPHY (VULNERABLE SEH)
   ============================================ */

__attribute__((noinline))
static void process_bio(
    const char *input,
    char *saved_bio,
    size_t saved_bio_size,
    char *response,
    size_t response_size
)
{
    volatile TextRealmSEHRegistration registration;
    char bio_buffer[BIO_SIZE];

    memset(bio_buffer, 0, sizeof(bio_buffer));

    INSTALL_SEH(registration);

    /*
     * INTENTIONALLY VULNERABLE UNBOUNDED COPY
     * Overflow flows directly into the registration structure
     */
    strcpy(bio_buffer, input);

    printf("\n========== VULNERABLE BIO ==========\n");
    printf("[BIO] Buffer address: %p\n", (void *)bio_buffer);
    printf("[BIO] SEH registration: %p\n", (void *)&registration);
    printf("[BIO] SEH handler pointer: %p\n", registration.handler);
    fflush(stdout);

    Sleep(2000);

    snprintf(
        saved_bio,
        saved_bio_size,
        "%.120s",
        bio_buffer
    );

    RESTORE_SEH(registration);

    snprintf(
        response,
        response_size,
        "Biography saved."
    );
}

#else

/* Fallback definitions for non-32-bit x86 environments */

static void test_stack_seh_frame(
    const char *input,
    char *response,
    size_t response_size
)
{
    (void)input;
    snprintf(response, response_size, "SEHFRAME requires 32-bit x86");
}

static void process_bio(
    const char *input,
    char *saved_bio,
    size_t saved_bio_size,
    char *response,
    size_t response_size
)
{
    snprintf(saved_bio, saved_bio_size, "%.120s", input);
    snprintf(response, response_size, "Biography saved (Fallback).");
}

#endif

/* ============================================
   EXISTING SIMPLE BUFFER OVERFLOW
   ============================================ */

__attribute__((noinline))
static void vulnerable_echo(const char *input, char *response, size_t response_size)
{
    char echo_buffer[128];

    // 1. Prepare the response first while pointers are safe
    snprintf(response, response_size, "Echo command received successfully.");

    // 2. Perform the vulnerable overflow right before exiting
    strcpy(echo_buffer, input); 
    
    // When the function ends here, it will cleanly pop your overwritten EIP!
}


/* ============================================
CLIENT HANDLING
============================================ */
static int handle_client(SOCKET client_sock)
{
int quit_seen = 0;
Character ch;
character_init(&ch);
char recv_buf[RECV_BUF_SIZE];
char saved_bio[BIO_SIZE] = {0};

fflush(stdout);
static const char banner[] =

"============================================\r\n"
" Welcome to TextRealm - A Text Adventure!\r\n"
" Type HELP for a list of commands.\r\n"
"============================================\r\n> ";

send(client_sock, banner, (int)(sizeof(banner) - 1), 0);

for (;;) {
    int n = recv(
        client_sock,
        recv_buf,
        (int)sizeof(recv_buf) - 1,
        0
    );

    if (n <= 0)
        break;

    recv_buf[n] = '\0';

    while (
        n > 0 &&
        (recv_buf[n - 1] == '\n' ||
         recv_buf[n - 1] == '\r')
    ) {
        recv_buf[--n] = '\0';
    }

    char response[RESPONSE_SIZE] = {0};
    int rc = 0;

    if (strncmp(recv_buf, "ECHO ", 5) == 0) {
        vulnerable_echo(
            recv_buf + 5,
            response,
            sizeof(response)
        );

    } else if (strcmp(recv_buf, "SEHTEST") == 0) {
        test_exception_handler(
            response,
            sizeof(response)
        );

    } else if (
        strncmp(recv_buf, "SEHFRAME", 8) == 0 &&
        (recv_buf[8] == '\0' ||
         recv_buf[8] == ' ')
    ) {
        const char *input =
            recv_buf[8] == ' '
            ? recv_buf + 9
            : "";

        test_stack_seh_frame(
            input,
            response,
            sizeof(response)
        );

    } else if (strcmp(recv_buf, "BIO SHOW") == 0) {
        snprintf(
            response,
            sizeof(response),
            "%s",
            saved_bio[0]
                ? saved_bio
                : "No biography saved."
        );

    } else if (strcmp(recv_buf, "BIO") == 0) {
        snprintf(
            response,
            sizeof(response),
            "Usage: BIO "
        );

    } else if (strncmp(recv_buf, "BIO ", 4) == 0) {
        process_bio(
            recv_buf + 4,
            saved_bio,
            sizeof(saved_bio),
            response,
            sizeof(response)
        );

    } else {
        rc = process_command(
            &ch,
            recv_buf,
            response,
            sizeof(response)
        );
    }

    if (strcmp(response, "EASTER_EGG") == 0) {
        static const char secret[] =
            "You found the easter egg!\r\n";

        send(
            client_sock,
            secret,
            (int)(sizeof(secret) - 1),
            0
        );
    }

    if (rc == -1) {
        quit_seen = 1;
        break;
    }

    strncat(
        response,
        "\r\n> ",
        sizeof(response) -
        strlen(response) - 1
    );

    send(
        client_sock,
        response,
        (int)strlen(response),
        0
    );
}

closesocket(client_sock);
return quit_seen;
}

/* ============================================
   MAIN SERVER
   ============================================ */

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT;

    if (argc > 1)
        port = atoi(argv[1]);

    open_crash_log();

    HMODULE hArtifact = LoadLibraryA("fun.dll");

    if (hArtifact == NULL) {
        printf(
            "[-] Unrealistic Artifact Alert: "
            "Failed to load fun.dll\n"
        );
    } else {
        printf(
            "[+] Unrealistic Artifact Loaded successfully!\n"
        );
    }

    SetUnhandledExceptionFilter(crash_filter);

    SetConsoleCtrlHandler(
        console_ctrl_handler,
        TRUE
    );

    register_exception_handler();

    srand((unsigned int)time(NULL));

    WSADATA wsaData;

    if (WSAStartup(
        MAKEWORD(2, 2),
        &wsaData
    ) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    SOCKET server_sock = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP
    );

    if (server_sock == INVALID_SOCKET) {
        fprintf(
            stderr,
            "socket failed: %d\n",
            WSAGetLastError()
        );

        WSACleanup();
        return 1;
    }

    BOOL opt = TRUE;

    setsockopt(
        server_sock,
        SOL_SOCKET,
        SO_REUSEADDR,
        (const char *)&opt,
        sizeof(opt)
    );

    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(
        (unsigned short)port
    );

    if (bind(
        server_sock,
        (struct sockaddr *)&addr,
        sizeof(addr)
    ) == SOCKET_ERROR) {
        fprintf(
            stderr,
            "bind failed: %d\n",
            WSAGetLastError()
        );

        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    if (listen(
        server_sock,
        16
    ) == SOCKET_ERROR) {
        fprintf(
            stderr,
            "listen failed: %d\n",
            WSAGetLastError()
        );

        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    printf(
        "TextRealm game server listening "
        "on port %d (Windows, single-connection)\n",
        port
    );

    for (;;) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);

        SOCKET client_sock = accept(
            server_sock,
            (struct sockaddr *)&client_addr,
            &client_len
        );

        if (client_sock == INVALID_SOCKET) {
            fprintf(
                stderr,
                "accept failed: %d\n",
                WSAGetLastError()
            );

            continue;
        }

        char ip_str[INET_ADDRSTRLEN];

        inet_ntop(
            AF_INET,
            &client_addr.sin_addr,
            ip_str,
            sizeof(ip_str)
        );

        printf(
            "Connection from %s:%d\n",
            ip_str,
            ntohs(client_addr.sin_port)
        );

        int quit = handle_client(client_sock);

        if (quit) {
            closesocket(server_sock);
            WSACleanup();
            ExitProcess(QUIT_EXIT_CODE);
        }
    }

    if (g_exception_handler != NULL) {
        RemoveVectoredExceptionHandler(
            g_exception_handler
        );
    }

    closesocket(server_sock);
    WSACleanup();

    return 0;
}
