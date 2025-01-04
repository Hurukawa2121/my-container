#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <fcntl.h>

#include "container.h"

#ifndef SCMP_FAIL
#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)
#endif

// pivot_root をラップ
static int pivot_root_syscall(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

int capabilities(void) {
    fprintf(stderr, "=> dropping capabilities...\n");

    int drop_caps[] = {
        CAP_AUDIT_CONTROL,
        CAP_AUDIT_READ,
        CAP_AUDIT_WRITE,
        CAP_BLOCK_SUSPEND,
        CAP_DAC_READ_SEARCH,
        CAP_FSETID,
        CAP_IPC_LOCK,
        CAP_MAC_ADMIN,
        CAP_MAC_OVERRIDE,
        CAP_MKNOD,
        CAP_SETFCAP,
        CAP_SYSLOG,
        CAP_SYS_ADMIN,
        CAP_SYS_BOOT,
        CAP_SYS_MODULE,
        CAP_SYS_NICE,
        CAP_SYS_RAWIO,
        CAP_SYS_RESOURCE,
        CAP_SYS_TIME,
        CAP_WAKE_ALARM
    };
    size_t num_caps = sizeof(drop_caps) / sizeof(drop_caps[0]);

    fprintf(stderr, "   bounding...");
    // bounding set から drop
    for (size_t i = 0; i < num_caps; i++) {
        if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0)) {
            perror("prctl(PR_CAPBSET_DROP) failed");
            return -1;
        }
    }

    // inheritable set を削除 (アンビエントセットもクリア)
    fprintf(stderr, "   inheritable...");
    cap_t caps = cap_get_proc();
    if (!caps) {
        perror("cap_get_proc failed");
        return -1;
    }
    if (cap_set_flag(caps, CAP_INHERITABLE, (int)num_caps, drop_caps, CAP_CLEAR)) {
        perror("cap_set_flag failed");
        cap_free(caps);
        return -1;
    }
    if (cap_set_proc(caps)) {
        perror("cap_set_proc failed");
        cap_free(caps);
        return -1;
    }
    cap_free(caps);

    fprintf(stderr, "done.\n");
    return 0;
}

int syscalls(void) {
    fprintf(stderr, "=> filtering syscalls...\n");
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        perror("seccomp_init failed");
        return -1;
    }

    // setuid/setgidビットを立てる chmod 系禁止
    if (seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
                         SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) != 0
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
                         SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) != 0
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
                         SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) != 0
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
                         SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) != 0
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
                         SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) != 0
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
                         SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) != 0

     // user namespace
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(unshare), 1,
                         SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)) != 0
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clone), 1,
                         SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)) != 0

     // ioctl(TIOCSTI)
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1,
                         SCMP_A1(SCMP_CMP_MASKED_EQ, TIOCSTI, TIOCSTI)) != 0

     // keyring 系
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0) != 0
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0) != 0
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0) != 0

     // ptrace
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0) != 0

     // NUMA 系
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0) != 0
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0) != 0
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0) != 0
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0) != 0

     // userfaultfd
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0) != 0

     // perf_event_open
     || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(perf_event_open), 0) != 0

     // PR_SET_NO_NEW_PRIVS → 0
     || seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0) != 0) {

        perror("seccomp_rule_add or seccomp_attr_set failed");
        seccomp_release(ctx);
        return -1;
    }

    // 適用
    if (seccomp_load(ctx) != 0) {
        perror("seccomp_load failed");
        seccomp_release(ctx);
        return -1;
    }
    seccomp_release(ctx);

    fprintf(stderr, "=> syscalls filtered.\n");
    return 0;
}

int mounts(struct child_config *config) {
    fprintf(stderr, "=> remounting everything with MS_PRIVATE...\n");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
        perror("mount MS_PRIVATE failed");
        return -1;
    }

    // 一時ディレクトリ + bindマウント
    char mount_dir[] = "/tmp/tmp.XXXXXX";
    if (!mkdtemp(mount_dir)) {
        perror("mkdtemp failed");
        return -1;
    }

    if (mount(config->mount_dir, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
        perror("bind mount failed");
        return -1;
    }

    char inner_mount_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
    memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);

    if (!mkdtemp(inner_mount_dir)) {
        perror("mkdtemp inner failed");
        return -1;
    }

    // pivot_root
    if (pivot_root_syscall(mount_dir, inner_mount_dir)) {
        perror("pivot_root failed");
        return -1;
    }

    // old root をアンマウント
    char *old_root_dir = basename(inner_mount_dir);
    char old_root[1024] = "/";
    strncat(old_root, old_root_dir, sizeof(old_root) - 2);

    if (chdir("/")) {
        perror("chdir / failed");
        return -1;
    }
    if (umount2(old_root, MNT_DETACH)) {
        perror("umount old_root failed");
        return -1;
    }
    if (rmdir(old_root)) {
        perror("rmdir old_root failed");
        return -1;
    }

    fprintf(stderr, "=> mounts done.\n");
    return 0;
}
