#ifndef CONTAINER_H
#define CONTAINER_H

#include <sys/types.h>

// 子プロセス用のコンフィグ
struct child_config {
    int     argc;
    uid_t   uid;
    int     fd;
    char   *hostname;
    char  **argv;
    char   *mount_dir;
};

// 関数プロトタイプ
int drop_capabilities(void);
int restrict_syscalls(void);
int mounts(struct child_config *config);

#endif
