#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "child.h"
#include "container.h"
#include "resources.h"
#include "userns.h"

// 適当なホスト名を決める
static int choose_hostname(char *buff, size_t len) {
    snprintf(buff, len, "mycontainer-%d", getpid());
    return 0;
}

int main(int argc, char **argv) {
    struct child_config config;
    memset(&config, 0, sizeof(config));

    int sockets[2] = {0};
    pid_t child_pid = 0;
    int opt = 0;

    // デフォルト値
    config.uid = 1000;  // 例: 非特権ユーザID
    config.mount_dir = NULL;

    // オプション解析 (例: -u 1000, -m /some/dir, -c /bin/sh)
    while ((opt = getopt(argc, argv, "u:m:c:")) != -1) {
        switch (opt) {
        case 'u':
            config.uid = atoi(optarg);
            break;
        case 'm':
            config.mount_dir = optarg;
            break;
        case 'c':
            // 残りをコマンドとして扱う
            config.argc = argc - optind + 1;
            config.argv = &argv[optind - 1];
            optind = argc; // ループ終了
            break;
        default:
            fprintf(stderr, "Usage: %s -u UID -m MOUNTDIR -c COMMAND [ARGS...]\n", argv[0]);
            return 1;
        }
    }

    if (!config.argc || !config.mount_dir) {
        fprintf(stderr, "Usage: %s -u UID -m /path -c /bin/sh [args]\n", argv[0]);
        return 1;
    }

    // Linuxバージョンチェック
    struct utsname host;
    if (uname(&host) < 0) {
        perror("uname failed");
        return 1;
    }
    fprintf(stderr, "Running on %s %s\n", host.sysname, host.release);

    char hostname[256] = {0};
    choose_hostname(hostname, sizeof(hostname));
    config.hostname = hostname;

    // ソケットペア作成
    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets) != 0) {
        perror("socketpair failed");
        return 1;
    }
    // FD_CLOEXEC
    if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC) != 0) {
        perror("fcntl failed");
        return 1;
    }
    config.fd = sockets[1];

    // cgroupなどリソース設定
    if (resources(&config) != 0) {
        fprintf(stderr, "resources failed\n");
        close(sockets[0]);
        close(sockets[1]);
        return 1;
    }

    size_t STACK_SIZE = 1024 * 1024;
    void *stack = malloc(STACK_SIZE);
    if (!stack) {
        fprintf(stderr, "malloc stack failed\n");
        close(sockets[0]);
        close(sockets[1]);
        free_resources(&config);
        return 1;
    }

    int clone_flags = CLONE_NEWNS
                    | CLONE_NEWCGROUP
                    | CLONE_NEWPID
                    | CLONE_NEWIPC
                    | CLONE_NEWNET
                    | CLONE_NEWUTS
                    | SIGCHLD;

    child_pid = clone(child, (char*)stack + STACK_SIZE, clone_flags, &config);
    if (child_pid < 0) {
        perror("clone failed");
        free(stack);
        close(sockets[0]);
        close(sockets[1]);
        free_resources(&config);
        return 1;
    }
    close(sockets[1]); // 子側の fd を閉じる

    // ユーザー名前空間の UID/GID マップ設定
    if (handle_child_uid_map(child_pid, sockets[0]) != 0) {
        fprintf(stderr, "handle_child_uid_map failed\n");
        // 子プロセス終了待ち
        waitpid(child_pid, NULL, 0);
        free(stack);
        close(sockets[0]);
        free_resources(&config);
        return 1;
    }

    // 子プロセス終了待ち
    int status = 0;
    if (waitpid(child_pid, &status, 0) < 0) {
        perror("waitpid failed");
        status = 1;
    } else {
        if (WIFEXITED(status)) {
            status = WEXITSTATUS(status);
        } else {
            status = 1;
        }
    }

    // 後片付け
    free(stack);
    close(sockets[0]);
    free_resources(&config);
    return status;
}
