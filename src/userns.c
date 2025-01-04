#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <string.h>
#include <errno.h>

#include "userns.h"

#define USERNS_OFFSET 10000
#define USERNS_COUNT  2000

int handle_child_uid_map(pid_t child_pid, int fd) {
    int has_userns = -1;
    ssize_t read_bytes = read(fd, &has_userns, sizeof(has_userns));
    if (read_bytes != sizeof(has_userns)) {
        fprintf(stderr, "couldn't read from child!\n");
        return -1;
    }

    if (has_userns) {
        char path[PATH_MAX];
        for (char **file = (char*[]){"uid_map","gid_map",NULL}; *file; file++) {
            snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file);
            fprintf(stderr, "writing %s...\n", path);
            int uid_map_fd = open(path, O_WRONLY);
            if (uid_map_fd < 0) {
                perror("open uid_map failed");
                return -1;
            }
            dprintf(uid_map_fd, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT);
            close(uid_map_fd);
        }
    }

    // 書き戻す（子プロセスを再開させる）
    if (write(fd, &(int){0}, sizeof(int)) != sizeof(int)) {
        perror("write to child failed");
        return -1;
    }

    return 0;
}

int userns(struct child_config *config) {
    fprintf(stderr, "=> trying a user namespace...\n");

    int has_userns = !unshare(CLONE_NEWUSER);
    // 親プロセスへ "usernsが使えたか" を通知
    if (write(config->fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
        perror("write has_userns failed");
        return -1;
    }

    // 親プロセスが uid_map/gid_map を書き込むのを待つ
    int result = 0;
    if (read(config->fd, &result, sizeof(result)) != sizeof(result)) {
        perror("read result failed");
        return -1;
    }
    if (result != 0) {
        // parent側がエラーのとき
        return -1;
    }

    if (has_userns) {
        fprintf(stderr, "=> userns done.\n");
    } else {
        fprintf(stderr, "=> userns unsupported? continuing.\n");
    }
    return 0;
}
