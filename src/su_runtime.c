#define _GNU_SOURCE
#include "su_runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define SU_LINK       "/data/local/tmp/su"
#define SOCKET_NAME   "kgsl_su_root_v2"
#define POLL_MS       50
#define CLIENT_TIMEOUT_SECONDS 15

static int g_server_fd = -1;
static char g_exe_path[PATH_MAX];

static int write_all(int fd, const void *buffer, size_t length) {
    const unsigned char *p = buffer;
    while (length) {
        ssize_t n = write(fd, p, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            if (n == 0) errno = EIO;
            return -1;
        }
        p += n;
        length -= (size_t)n;
    }
    return 0;
}

static socklen_t make_socket_address(struct sockaddr_un *address) {
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    size_t length = strlen(SOCKET_NAME);
    address->sun_path[0] = '\0';
    memcpy(address->sun_path + 1, SOCKET_NAME, length);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + length);
}

static int create_server_socket(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_un address;
    socklen_t length = make_socket_address(&address);
    if (bind(fd, (struct sockaddr *)&address, length) < 0 ||
        listen(fd, 4) < 0) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }

    if (fd < 4) {
        int moved = fcntl(fd, F_DUPFD_CLOEXEC, 4);
        if (moved < 0) {
            int error = errno;
            close(fd);
            errno = error;
            return -1;
        }
        close(fd);
        fd = moved;
    }
    return fd;
}

static int connect_server(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_un address;
    socklen_t length = make_socket_address(&address);
    if (connect(fd, (struct sockaddr *)&address, length) < 0) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

static int probe_server(int timeout_ms) {
    int fd = connect_server();
    if (fd < 0) return -1;

    const char request = 'H';
    char response = 0;
    int rc = write_all(fd, &request, sizeof(request));
    if (rc == 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLHUP | POLLERR };
        do { rc = poll(&pfd, 1, timeout_ms); } while (rc < 0 && errno == EINTR);
        if (rc > 0 && (pfd.revents & POLLIN)) {
            ssize_t n;
            do { n = read(fd, &response, sizeof(response)); }
            while (n < 0 && errno == EINTR);
            rc = n == 1 && response == 'R' ? 0 : -1;
        } else {
            if (rc == 0) errno = ETIMEDOUT;
            rc = -1;
        }
    }
    int error = errno;
    close(fd);
    errno = error;
    return rc;
}

int su_runtime_wait_ready(int timeout_ms) {
    if (timeout_ms < 0) timeout_ms = 0;
    int remaining = timeout_ms;
    for (;;) {
        int slice = remaining > POLL_MS ? POLL_MS : remaining;
        if (probe_server(slice) == 0) return 0;
        if (remaining == 0) break;
        if (slice > 0) {
            usleep((useconds_t)slice * 1000);
            remaining -= slice;
        } else {
            break;
        }
    }
    errno = ETIMEDOUT;
    return -1;
}

static void set_shell_environment(void) {
    (void)prctl(PR_SET_NAME, "kgsl_su_shell", 0, 0, 0);
    (void)setenv("SHELL", "/system/bin/sh", 1);
    (void)setenv("USER", "root", 1);
    (void)setenv("LOGNAME", "root", 1);
    (void)setenv("HOME", "/data/local/tmp", 1);
    (void)setenv("PATH", "/system/bin:/system/xbin:/vendor/bin", 1);
    (void)setenv("PS1", "# ", 1);
}

static int attach_socket_stdio(int fd) {
    if (dup2(fd, STDIN_FILENO) < 0 ||
        dup2(fd, STDOUT_FILENO) < 0 ||
        dup2(fd, STDERR_FILENO) < 0)
        return -1;
    if (fd > STDERR_FILENO) close(fd);
    return 0;
}

/*
 * A command's shell keeps running while the daemon returns to accept(), so
 * concurrent su clients do not queue behind each other.  Children are reaped
 * by SIGCHLD auto-reaping, and a client that stalls mid-request is dropped
 * instead of blocking the service.
 */
static void prepare_client(int fd) {
    struct timeval timeout = {
        .tv_sec = CLIENT_TIMEOUT_SECONDS,
        .tv_usec = 0,
    };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

static int run_command(int socket_fd) {
    size_t capacity = 4096;
    size_t used = 0;
    char *command = malloc(capacity);
    if (!command) {
        close(socket_fd);
        return -1;
    }

    for (;;) {
        if (used + 2048 + 1 > capacity) {
            if (capacity >= 1024 * 1024) {
                free(command);
                close(socket_fd);
                errno = E2BIG;
                return -1;
            }
            size_t next = capacity * 2;
            if (next > 1024 * 1024) next = 1024 * 1024;
            char *grown = realloc(command, next);
            if (!grown) {
                free(command);
                close(socket_fd);
                return -1;
            }
            command = grown;
            capacity = next;
        }
        ssize_t n = read(socket_fd, command + used, capacity - used - 1);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            free(command);
            close(socket_fd);
            return -1;
        }
        if (n == 0) break;
        used += (size_t)n;
        if (used >= 1024 * 1024) {
            free(command);
            close(socket_fd);
            errno = E2BIG;
            return -1;
        }
    }
    command[used] = '\0';

    pid_t shell = fork();
    if (shell < 0) {
        free(command);
        close(socket_fd);
        return -1;
    }
    if (shell == 0) {
        if (attach_socket_stdio(socket_fd) < 0) _exit(126);
        set_shell_environment();
        char *arguments[] = {
            (char *)"sh", (char *)"-p", (char *)"-c", command, NULL
        };
        execve("/system/bin/sh", arguments, environ);
        _exit(127);
    }

    free(command);
    close(socket_fd);
    return 0;
}

static int run_interactive(int socket_fd) {
    pid_t shell = fork();
    if (shell < 0) {
        close(socket_fd);
        return -1;
    }
    if (shell == 0) {
        if (attach_socket_stdio(socket_fd) < 0) _exit(126);
        set_shell_environment();
        char *arguments[] = {
            (char *)"sh", (char *)"-p", (char *)"-i", NULL
        };
        execve("/system/bin/sh", arguments, environ);
        _exit(127);
    }

    close(socket_fd);
    return 0;
}

static int serve_clients(volatile int *stage) {
    if (g_server_fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (stage) *stage = 6;

    for (;;) {
        struct pollfd pfd = { .fd = g_server_fd, .events = POLLIN };
        int ready;
        do { ready = poll(&pfd, 1, 200); } while (ready < 0 && errno == EINTR);
        if (ready < 0) return -1;
        if (ready == 0) continue;

        int client = accept(g_server_fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        prepare_client(client);

        char mode = 0;
        ssize_t n;
        do { n = read(client, &mode, 1); } while (n < 0 && errno == EINTR);
        if (n == 1 && mode == 'H') {
            const char response = 'R';
            (void)write_all(client, &response, sizeof(response));
            close(client);
        } else if (n == 1 && (mode == 'I' || mode == 'C')) {
            if (mode == 'I') (void)run_interactive(client);
            else (void)run_command(client);
        } else {
            close(client);
        }
    }
}

static int daemon_entry(volatile int *stage) {
    if (stage) *stage = 1;
    if (setsid() < 0) return -1;
    if (stage) *stage = 2;

    if (geteuid() != 0 || getegid() != 0) {
        errno = EPERM;
        return -1;
    }
    if (stage) *stage = 3;

    (void)prctl(PR_SET_NAME, "kgsl_su_rootd", 0, 0, 0);
    (void)umask(077);
    if (chdir("/") < 0) return -1;
    if (stage) *stage = 4;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    if (stage) *stage = 5;
    return serve_clients(stage);
}

int su_runtime_start_daemon(volatile int *stage) {
    return daemon_entry(stage);
}

int su_runtime_prepare(void) {
    ssize_t length = readlink("/proc/self/exe", g_exe_path,
                              sizeof(g_exe_path) - 1);
    if (length < 0) return -1;
    g_exe_path[length] = '\0';

    char link_target[PATH_MAX];
    ssize_t link_length = readlink(SU_LINK, link_target,
                                   sizeof(link_target) - 1);
    if (link_length < 0 ||
        (size_t)link_length >= sizeof(link_target) - 1 ||
        (size_t)link_length != strlen(g_exe_path) ||
        memcmp(link_target, g_exe_path, (size_t)link_length) != 0) {
        if (unlink(SU_LINK) < 0 && errno != ENOENT) return -1;
        if (symlink(g_exe_path, SU_LINK) < 0) return -1;
    }

    if (g_server_fd >= 0) close(g_server_fd);
    g_server_fd = create_server_socket();
    return g_server_fd < 0 ? -1 : 0;
}

void su_runtime_close_prepared_server_socket(void) {
    if (g_server_fd >= 0) close(g_server_fd);
    g_server_fd = -1;
}

static int send_command(int fd, int argc, char **argv) {
    size_t length = sizeof("\nexit\n") - 1;
    for (int i = 2; i < argc; i++) {
        size_t part = strlen(argv[i]);
        if (length > SIZE_MAX - part - 1) {
            errno = EOVERFLOW;
            return -1;
        }
        length += part + (i > 2 ? 1 : 0);
    }

    char *command = malloc(length);
    if (!command) return -1;
    size_t used = 0;
    for (int i = 2; i < argc; i++) {
        if (i > 2) command[used++] = ' ';
        size_t part = strlen(argv[i]);
        memcpy(command + used, argv[i], part);
        used += part;
    }
    memcpy(command + used, "\nexit\n", sizeof("\nexit\n") - 1);
    used += sizeof("\nexit\n") - 1;

    int rc = write_all(fd, command, used);
    int error = errno;
    free(command);
    errno = error;
    return rc;
}

static int su_client(int argc, char **argv) {
    if (argc == 2 &&
        (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        dprintf(STDOUT_FILENO, "usage: su [-c command]\n");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--stop") == 0) {
        dprintf(STDERR_FILENO,
                "su: stop the service with a normal Android reboot\n");
        return 2;
    }

    int command_mode = argc >= 3 && strcmp(argv[1], "-c") == 0;
    if (argc != 1 && !command_mode) {
        dprintf(STDERR_FILENO, "usage: su [-c command]\n");
        return 2;
    }

    if (su_runtime_wait_ready(1000) < 0) {
        dprintf(STDERR_FILENO, "su: root service is not running\n");
        return 1;
    }
    int fd = connect_server();
    if (fd < 0) {
        dprintf(STDERR_FILENO, "su: connect root service: %s\n",
                strerror(errno));
        return 1;
    }

    char mode = command_mode ? 'C' : 'I';
    if (write_all(fd, &mode, 1) < 0) {
        close(fd);
        return 1;
    }

    if (command_mode) {
        if (send_command(fd, argc, argv) < 0) {
            dprintf(STDERR_FILENO, "su: send command: %s\n", strerror(errno));
            close(fd);
            return 1;
        }
        (void)shutdown(fd, SHUT_WR);
        unsigned char buffer[4096];
        for (;;) {
            ssize_t n = read(fd, buffer, sizeof(buffer));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            if (write_all(STDOUT_FILENO, buffer, (size_t)n) < 0) break;
        }
        close(fd);
        return 0;
    }

    int input_open = 1;
    for (;;) {
        struct pollfd fds[2] = {
            { .fd = input_open ? STDIN_FILENO : -1,
              .events = POLLIN | POLLHUP | POLLERR },
            { .fd = fd, .events = POLLIN | POLLHUP | POLLERR }
        };
        int ready;
        do { ready = poll(fds, 2, -1); } while (ready < 0 && errno == EINTR);
        if (ready < 0) break;

        if (input_open && fds[0].revents) {
            unsigned char buffer[4096];
            ssize_t n = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (n > 0) {
                if (write_all(fd, buffer, (size_t)n) < 0) break;
            } else {
                input_open = 0;
                (void)shutdown(fd, SHUT_WR);
            }
        }

        if (fds[1].revents) {
            unsigned char buffer[4096];
            ssize_t n = read(fd, buffer, sizeof(buffer));
            if (n > 0) {
                if (write_all(STDOUT_FILENO, buffer, (size_t)n) < 0) break;
            } else {
                break;
            }
        }
    }

    close(fd);
    return 0;
}

int su_runtime_dispatch(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    const char *base = strrchr(argv[0], '/');
    base = base ? base + 1 : argv[0];
    if (strcmp(base, "su") == 0) return su_client(argc, argv);
    return -1;
}
