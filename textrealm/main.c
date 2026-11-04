/*
 * main.c - TextRealm supervisor.
 *
 * Supervisor wrapper for game server to make it easier on the end user. 
 *
 * The server signals a legitimate client QUIT by exiting with
 * QUIT_EXIT_CODE (218). On seeing that, the supervisor exits silently
 * and does not respawn anything.
 *
 * Everything is logged to one persistent file, game_logs/textrealm.log,
 * which is only ever appended to (it survives supervisor restarts). Each
 * run is marked with a start line. Any server exit other than 218 is
 * logged as a CRASH along with its exit code or fatal signal.
 *
 * Build:  cosmocc -O2 -o textrealm.com main.c
 * Usage:  ./textrealm.com             (takes no arguments)
 */

#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef __COSMOPOLITAN__
#include <cosmo.h>
#else
/* Plain-compiler fallback so the supervisor logic can be tested natively. */
static int IsWindows(void) { return 0; }
#endif

#define QUIT_EXIT_CODE   218
#define LOG_DIR          "game_logs"
#define LOG_FILE         "textrealm.log"
#define LINUX_SERVER     "linux/textrealm_server"
#define WINDOWS_SERVER   "windows/textrealm_server.exe"
#define PATH_MAX_LEN     4096
#define QUICK_DEATH_SECS 3   /* dying faster than this triggers a backoff */
#define MAX_BACKOFF_SECS 5

extern char **environ;

static FILE *g_log;
static volatile sig_atomic_t g_child = 0;      /* current server PID */
static volatile sig_atomic_t g_stop  = 0;      /* supervisor told to stop */

/* ---------------------------------------------------------------- logging */

static void log_msg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void log_msg(const char *fmt, ...) {
    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    /* Log file (if open) */
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

/*
 * Base directory = the directory main itself lives in (textrealm/), taken
 * from the absolute path of the running executable. Everything else
 * (linux/, windows/, game_logs/) is reached from here.
 */
static int get_base_dir(char *out, size_t cap) {
    char exe[PATH_MAX_LEN];
#ifdef __COSMOPOLITAN__
    const char *self = GetProgramExecutableName();
#else
    const char *self = "/proc/self/exe";
#endif
    if (!self || !realpath(self, exe)) return -1;

    char *slash = strrchr(exe, '/');
    char *bslash = strrchr(exe, '\\');
    if (bslash && (!slash || bslash > slash)) slash = bslash;
    if (!slash) return -1;
    if (slash == exe) slash++;           /* executable sits in the root dir */
    *slash = '\0';
    snprintf(out, cap, "%s", exe);
    return 0;
}

static int open_log(const char *base) {
    char dir[PATH_MAX_LEN + 16], path[PATH_MAX_LEN + 64];
    snprintf(dir, sizeof(dir), "%s/%s", base, LOG_DIR);
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "cannot create %s: %s\n", dir, strerror(errno));
        return -1;
    }
    snprintf(path, sizeof(path), "%s/%s", dir, LOG_FILE);
    g_log = fopen(path, "a");
    if (!g_log) {
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------- signals */

static void on_stop_signal(int sig) {
    (void)sig;
    g_stop = 1;
    if (g_child > 0) kill((pid_t)g_child, SIGTERM);
}

/* ------------------------------------------------------------- supervisor */

/*
 * Run `server_path` forever, respawning it when it dies. Returns when the
 * server exits with QUIT_EXIT_CODE or the supervisor is signalled.
 */
static int supervise(const char *server_path, const char *label) {
    char *child_argv[] = { (char *)server_path, NULL };

    int quick_deaths = 0;
    int respawns = 0;
    pid_t last_pid = 0;
    log_msg("supervisor started (%s), server binary: %s", label, server_path);

    while (!g_stop) {
        pid_t pid;
        time_t started = time(NULL);
        int rc = posix_spawn(&pid, server_path, NULL, NULL, child_argv, environ);
        if (rc != 0) {
            log_msg("SPAWN FAILED for %s: %s", server_path, strerror(rc));
            quick_deaths++;
        } else {
            g_child = pid;
            if (last_pid == 0)
                log_msg("SPAWN %s pid=%d", label, (int)pid);
            else
                log_msg("RESPAWN OK %s new pid=%d (previous pid=%d died, respawn #%d)",
                        label, (int)pid, (int)last_pid, ++respawns);
            last_pid = pid;

            int status = 0;
            pid_t w;
            while ((w = waitpid(pid, &status, 0)) < 0 && errno == EINTR) {}
            g_child = 0;

            if (w < 0) {
                log_msg("waitpid failed for pid=%d: %s", (int)pid, strerror(errno));
            } else if (WIFEXITED(status) && WEXITSTATUS(status) == QUIT_EXIT_CODE) {
                log_msg("DEATH %s pid=%d exit code %d (client QUIT) - "
                        "shutting down supervisor", label, (int)pid, QUIT_EXIT_CODE);
                return 0;
            } else if (WIFEXITED(status) && WEXITSTATUS(status) == 130) {
                log_msg("INTERRUPTED %s pid=%d exited with code 130 (SIGINT)",
                        label, (int)pid);
            } else if (WIFEXITED(status)) {
                log_msg("CRASH %s pid=%d exited with error code %d",
                        label, (int)pid, WEXITSTATUS(status));
            } else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGINT) {
                log_msg("INTERRUPTED %s pid=%d killed by SIGINT (error code 130)",
                        label, (int)pid);
            } else if (WIFSIGNALED(status)) {
                log_msg("CRASH %s pid=%d killed by signal %d (error code %d)",
                        label, (int)pid, WTERMSIG(status), 128 + WTERMSIG(status));
            } else {
                log_msg("CRASH %s pid=%d unknown status=0x%x", label, (int)pid, status);
            }

            if (g_stop) break;
            if (time(NULL) - started < QUICK_DEATH_SECS) quick_deaths++;
            else quick_deaths = 0;
        }

        if (quick_deaths > 0) {
            int delay = quick_deaths < MAX_BACKOFF_SECS ? quick_deaths : MAX_BACKOFF_SECS;
            log_msg("server died quickly, waiting %ds before respawn", delay);
            sleep((unsigned)delay);
        }
    }

    log_msg("supervisor stopping on signal");
    return 0;
}

static int run_linux(const char *base) {
    char path[PATH_MAX_LEN + 64];
    snprintf(path, sizeof(path), "%s/%s", base, LINUX_SERVER);
    return supervise(path, "textrealm_server (linux)");
}

static int run_windows(const char *base) {
    char path[PATH_MAX_LEN + 64];
    snprintf(path, sizeof(path), "%s/%s", base, WINDOWS_SERVER);
    return supervise(path, "textrealm_server (windows)");
}

/*
 * Make sure the server binary for this OS exists under base. If it does
 * not, main was most likely moved out of the textrealm project directory.
 * Reported on stderr (no log yet: we must not create game_logs/ elsewhere).
 */
static void require_project_dir(const char *base, const char *server_rel) {
    char path[PATH_MAX_LEN + 64];
    snprintf(path, sizeof(path), "%s/%s", base, server_rel);
    if (access(path, X_OK) == 0) return;

    fprintf(stderr,
            "error: cannot find %s\n"
            "You are likely not running this program from the 'textrealm' "
            "project directory (looked in %s).\n"
            "Run main from inside textrealm/, next to the linux/ and windows/ folders.\n",
            path, base);
    exit(1);
}

int main(int argc, char **argv) {
    char base[PATH_MAX_LEN];
    if (argc > 1) {
        fprintf(stderr, "%s needs no arguments\n", argv[0]);
        exit(1);
    }
    if (get_base_dir(base, sizeof(base)) != 0) {
        fprintf(stderr, "cannot determine the executable's directory\n");
        return 1;
    }
    require_project_dir(base, IsWindows() ? WINDOWS_SERVER : LINUX_SERVER);
    if (open_log(base) != 0) return 1;

    signal(SIGINT, on_stop_signal);
    signal(SIGTERM, on_stop_signal);

    int rc;
    switch (IsWindows()) {
        case 0:  rc = run_linux(base);   break;
        default: rc = run_windows(base); break;
    }

    fclose(g_log);
    return rc;
}
