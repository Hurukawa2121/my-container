#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <string.h>
#include <errno.h>

#include "resources.h"

#define MEMORY "1073741824" // 1GB
#define SHARES "256"
#define PIDS   "64"
#define WEIGHT "10"
#define FD_COUNT 64

struct cgrp_setting {
    char name[256];
    char value[256];
};

struct cgrp_control {
    char control[256];
    struct cgrp_setting **settings;
};

static struct cgrp_setting add_to_tasks = {
    .name = "tasks",
    .value = "0"
};

// cgroups配列
static struct cgrp_control *cgrps[] = {
    &(struct cgrp_control){
        .control = "memory",
        .settings = (struct cgrp_setting *[]) {
            &(struct cgrp_setting){ .name = "memory.limit_in_bytes", .value = MEMORY },
            &(struct cgrp_setting){ .name = "memory.kmem.limit_in_bytes", .value = MEMORY },
            &add_to_tasks,
            NULL
        }
    },
    &(struct cgrp_control){
        .control = "cpu",
        .settings = (struct cgrp_setting *[]) {
            &(struct cgrp_setting){ .name = "cpu.shares", .value = SHARES },
            &add_to_tasks,
            NULL
        }
    },
    &(struct cgrp_control){
        .control = "pids",
        .settings = (struct cgrp_setting *[]) {
            &(struct cgrp_setting){ .name = "pids.max", .value = PIDS },
            &add_to_tasks,
            NULL
        }
    },
    &(struct cgrp_control){
        .control = "blkio",
        .settings = (struct cgrp_setting *[]) {
            &(struct cgrp_setting){ .name = "blkio.weight", .value = WEIGHT },
            &add_to_tasks,
            NULL
        }
    },
    NULL
};

int resources(struct child_config *config) {
    fprintf(stderr, "=> setting cgroups...\n");
    // cgroupディレクトリを作って設定
    for (struct cgrp_control **cgrp = cgrps; *cgrp; cgrp++) {
        char dir[PATH_MAX];
        memset(dir, 0, sizeof(dir));
        snprintf(dir, sizeof(dir), "/sys/fs/cgroup/%s/%s", (*cgrp)->control, config->hostname);

        if (mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR) != 0) {
            if (errno != EEXIST) {
                perror("mkdir cgroup failed");
                return -1;
            }
        }
        // 各設定ファイルに書き込み
        for (struct cgrp_setting **setting = (*cgrp)->settings; *setting; setting++) {
            char path[PATH_MAX];
            memset(path, 0, sizeof(path));
            snprintf(path, sizeof(path), "%s/%s", dir, (*setting)->name);

            int fd = open(path, O_WRONLY);
            if (fd < 0) {
                perror("open cgroup setting failed");
                return -1;
            }
            if (write(fd, (*setting)->value, strlen((*setting)->value)) == -1) {
                perror("write cgroup setting failed");
                close(fd);
                return -1;
            }
            close(fd);
        }
    }

    // RLIMIT_NOFILE 制限
    fprintf(stderr, "=> setting rlimit NOFILE to %d...\n", FD_COUNT);
    struct rlimit rl = {
        .rlim_cur = FD_COUNT,
        .rlim_max = FD_COUNT
    };
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        perror("setrlimit failed");
        return -1;
    }

    fprintf(stderr, "done.\n");
    return 0;
}

int free_resources(struct child_config *config) {
    fprintf(stderr, "=> cleaning cgroups...\n");
    for (struct cgrp_control **cgrp = cgrps; *cgrp; cgrp++) {
        char dir[PATH_MAX];
        char task[PATH_MAX];
        memset(dir, 0, sizeof(dir));
        memset(task, 0, sizeof(task));

        snprintf(dir,  sizeof(dir),  "/sys/fs/cgroup/%s/%s", (*cgrp)->control, config->hostname);
        snprintf(task, sizeof(task), "/sys/fs/cgroup/%s/tasks", (*cgrp)->control);

        // タスクを root cgroup に戻す ( "0" = current process )
        int tfd = open(task, O_WRONLY);
        if (tfd < 0) {
            perror("open tasks failed");
            continue;
        }
        if (write(tfd, "0", 2) < 0) {
            perror("write tasks failed");
        }
        close(tfd);

        // ディレクトリ削除
        if (rmdir(dir) != 0) {
            perror("rmdir cgroup failed");
        }
    }
    fprintf(stderr, "done.\n");
    return 0;
}
