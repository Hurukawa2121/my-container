#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <grp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "child.h"
#include "container.h"
#include "userns.h"

int child(void *arg) {
    struct child_config *config = (struct child_config*) arg;
    // ホスト名設定
    if (sethostname(config->hostname, strlen(config->hostname)) != 0) {
        perror("sethostname failed");
        return -1;
    }

    if (mounts(config) != 0) {
        fprintf(stderr, "mounts failed\n");
        return -1;
    }

    if (userns(config) != 0) {
        fprintf(stderr, "userns failed\n");
        return -1;
    }

    // userns 内で uid/gidを切り替え
    fprintf(stderr, "=> switching to uid %d / gid %d...\n", config->uid, config->uid);
    if (setgroups(1, (gid_t[]){config->uid}) ||
        setresgid(config->uid, config->uid, config->uid) ||
        setresuid(config->uid, config->uid, config->uid)) {
        perror("failed setresuid/setresgid");
        return -1;
    }

    if (capabilities() != 0) {
        fprintf(stderr, "capabilities() failed\n");
        return -1;
    }
    if (syscalls() != 0) {
        fprintf(stderr, "syscalls() failed\n");
        return -1;
    }

    if (close(config->fd) != 0) {
        perror("close fd");
        return -1;
    }

    // 実行
    fprintf(stderr, "=> execve(%s)...\n", config->argv[0]);
    if (execve(config->argv[0], config->argv, NULL) != 0) {
        perror("execve failed");
        return -1;
    }
    return EXIT_SUCCESS;
}
