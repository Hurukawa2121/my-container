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


bool set_config(struct child_config *config) {
    if (sethostname(config->hostname, strlen(config->hostname)) < 0) {
        perror("sethostname failed");
        return false;
    }

    if (mounts(config) < 0) {
        fprintf(stderr, "mounts failed\n");
        return false;
    }

    if (userns(config) < 0) {
        fprintf(stderr, "userns failed\n");
        return false;
    }
    return true;
}

bool switch_uid_gid(int uid, int gid) {
    if (setgroups(1, (gid_t[]){uid}) ||
        setresgid(uid, uid, uid) ||
        setresuid(uid, uid, uid)) {
        perror("failed setresuid/setresgid");
        return false;
    }

    if (capabilities() < 0) {
        fprintf(stderr, "capabilities() failed\n");
        return false;
    }
    if (syscalls() < 0) {
        fprintf(stderr, "syscalls() failed\n");
        return false;
    }

    if (close(config->fd) < 0) {
        perror("close fd");
        return false;
    }
    return true;
}

int child(void *arg) {
    struct child_config *config = (struct child_config*) arg;

    // ホスト名設定
    if (!set_config(config)) {
        return -1;
    }

    // userns 内で uid/gidを切り替え
    ffprintf(stderr, "=> switching to uid %d / gid %d...\n", uid, uid);
    if (!switch_uid_gid(config->uid, config->uid)) {
        return -1;
    }

    // 実行
    fprintf(stderr, "=> execve(%s)...\n", config->argv[0]);
    if (execve(config->argv[0], config->argv, NULL) < 0) {
        perror("execve failed");
        return -1;
    }
    return EXIT_SUCCESS;
}
