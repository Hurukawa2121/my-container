#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>

#include "container.h"

// cgroup v2 用リソース設定リスト
static struct cgrp_setting {
    char name[256];   // 例: "memory.max", "pids.max", "cpu.weight" 等
    char value[256];  // 例: "1073741824", "64", "256" など
} cgrp_settings[] = {
    { "memory.max",  "1073741824" }, // 1GB
    { "pids.max",    "64"         }, // プロセス数64
    // cgroup v2 では cpu.weight (1〜10000) でCPU割合を指定
    { "cpu.weight",  "256"       },  // 例: 256 (旧v1のcpu.shares=256相当)
    // blkio => cgroup v2では "io.weight" (1〜1000,スケジューラ依存)
    { "io.weight",   "50"        },  // 例: 50
    { "", "" } // 終端
};

// cgroup v2のディレクトリを作成し、リソースを設定する
int resources(struct child_config *config)
{
    fprintf(stderr, "=> setting cgroups (v2)...\n");

    // 1. 親cgroupの subtree_control を有効化
    //    (root cgroupの "/sys/fs/cgroup/cgroup.subtree_control" などに書き込み)
    {
        const char *parent_control = "/sys/fs/cgroup/cgroup.subtree_control";
        int fd = open(parent_control, O_WRONLY);
        if (fd < 0) {
            fprintf(stderr, "open %s failed: %m\n", parent_control);
            return -1;
        }
        // 有効にしたいコントローラ: memory, cpu, pids, ioなど
        const char *controllers = "+memory +cpu +pids +io";
        if (write(fd, controllers, strlen(controllers)) == -1) {
            fprintf(stderr, "writing to %s failed: %m\n", parent_control);
            close(fd);
            return -1;
        }
        close(fd);
    }

    // 2. cgroupディレクトリ "/sys/fs/cgroup/<hostname>" を作成
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "/sys/fs/cgroup/%s", config->hostname);

    if (mkdir(dir, 0755) && errno != EEXIST) {
        fprintf(stderr, "mkdir %s failed: %m\n", dir);
        return -1;
    }

    // 3. cgroup設定ファイル (memory.max 等) に値を書き込み
    for (int i = 0; cgrp_settings[i].name[0] != '\0'; i++) {
        char path[PATH_MAX * 2];
        snprintf(path, sizeof(path), "%s/%s", dir, cgrp_settings[i].name);

        int fd = open(path, O_WRONLY);
        if (fd < 0) {
            fprintf(stderr, "open %s failed: %m\n", path);
            return -1;
        }
        if (write(fd, cgrp_settings[i].value, strlen(cgrp_settings[i].value)) == -1) {
            fprintf(stderr, "write to %s failed: %m\n", path);
            close(fd);
            return -1;
        }
        close(fd);
    }

    // 4. cgroup.procs に "0" を書き込んで、このプロセスを所属させる
    {
        char procs_path[PATH_MAX * 2];
        snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", dir);

        int fd = open(procs_path, O_WRONLY);
        if (fd < 0) {
            fprintf(stderr, "open %s failed: %m\n", procs_path);
            return -1;
        }
        if (write(fd, "0", 1) == -1) {
            fprintf(stderr, "write to %s failed: %m\n", procs_path);
            close(fd);
            return -1;
        }
        close(fd);
    }

    // 5. 他のリソース制限 (ulimit相当)
    fprintf(stderr, "=> setting rlimit NOFILE to 64...\n");
    struct rlimit rl = {
        .rlim_cur = 64,
        .rlim_max = 64
    };
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "setrlimit(RLIMIT_NOFILE) failed: %m\n");
        return -1;
    }

    fprintf(stderr, "=> cgroup v2 done.\n");
    return EXIT_SUCCESS;
}

int free_resources(struct child_config *config) {
    fprintf(stderr, "=> cleaning cgroups (v2)...\n");

    // プロセスが残っていると削除できないので
    // move processes out from /sys/fs/cgroup/testhostname
    char parent_cgroup[] = "/sys/fs/cgroup/cgroup.procs"; // root cgroup
    char my_pid[32];
    snprintf(my_pid, sizeof(my_pid), "%d", getpid());

    int fd = open(parent_cgroup, O_WRONLY);
    if (fd >= 0) {
        write(fd, my_pid, strlen(my_pid));
        close(fd);
    }

    // cgroupディレクトリを削除する
    char dir[PATH_MAX * 2];
    snprintf(dir, sizeof(dir), "/sys/fs/cgroup/%s", config->hostname);

    // cgroup内のプロセスを抜いてから (parent cgroupに移動)
    if (rmdir(dir) < 0) {
        fprintf(stderr, "rmdir %s failed: %m\n", dir);
        // 続行は可能だが、ここではエラー扱い
        return -1;
    }

    fprintf(stderr, "done.\n");
    return EXIT_SUCCESS;
}

