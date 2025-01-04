#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <fcntl.h>
#include <libgen.h>   // basename()

#include "container.h"

#ifndef SCMP_FAIL
#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)
#endif

//------------------------------------------------------
// 1. drop_capabilities 関連
//------------------------------------------------------

/**
 * @brief Drop the inheritable drop_capabilities from the current process.
 *        On success => true, failure => false.
 */
static bool drop_inheritable_caps(size_t num_capabilities, const int *capabilities_to_drop) {
    cap_t capabilities = cap_get_proc();
    if (!capabilities) {
        perror("cap_get_proc failed");
        return false;
    }
    // drop from inheritable set (アンビエントセットもクリアされる)
    if (cap_set_flag(capabilities, CAP_INHERITABLE, (int)num_capabilities, capabilities_to_drop, CAP_CLEAR)) {
        perror("cap_set_flag failed");
        cap_free(capabilities);
        return false;
    }
    if (cap_set_proc(capabilities)) {
        perror("cap_set_proc failed");
        cap_free(capabilities);
        return false;
    }
    cap_free(capabilities);
    return true;
}

/**
 * @brief Remove bounding set and inheritable capabilities.
 * @return 0 on success, -1 on failure
 */
int drop_capabilities(void) {
    fprintf(stderr, "=> dropping drop_capabilities...\n");

    int capabilities_to_drop[] = {
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
    size_t num_capabilities = sizeof(capabilities_to_drop) / sizeof(capabilities_to_drop[0]);

    fprintf(stderr, "   bounding...");
    // bounding set から drop
    for (size_t i = 0; i < num_capabilities; i++) {
        if (prctl(PR_CAPBSET_DROP, capabilities_to_drop[i], 0, 0, 0)) {
            perror("prctl(PR_CAPBSET_DROP) failed");
            return -1;
        }
    }

    fprintf(stderr, "   inheritable...");
    // inheritable set を削除
    if (!drop_inheritable_caps(num_capabilities, capabilities_to_drop)) {
        fprintf(stderr, "Failed to drop inheritable caps\n");
        return -1;
    }

    fprintf(stderr, "done.\n");
    return 0;
}

//------------------------------------------------------
// 2. restrict_syscalls (seccomp) 関連
//------------------------------------------------------

/**
 * @brief Create seccomp filter context with restricted syscalls.
 * @return scmp_filter_ctx, or NULL if something fails
 */
static scmp_filter_ctx create_secure_context(void) {
    // seccomp_init(SCMP_ACT_ALLOW) => デフォルト許可, 特定のsyscallのみ拒否
    scmp_filter_ctx context = seccomp_init(SCMP_ACT_ALLOW);
    if (!context) {
        perror("seccomp_init failed");
        return NULL;
    }

    // Helperマクロ: エラー時に context を解放して NULL return
#define RULE_FAIL_CHECK(expr) \
    do { \
        if ((expr) != 0) { \
            perror("seccomp_rule_add/set failed"); \
            seccomp_release(context); \
            return NULL; \
        } \
    } while(0)

    // setuid/setgidビットを立てる chmod 系禁止
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(chmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)));
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(chmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)));
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(fchmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)));
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(fchmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)));
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
                SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)));
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
                SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)));

    // user namespace
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(unshare), 1,
                SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)));
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(clone), 1,
                SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)));

    // ioctl(TIOCSTI)
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(ioctl), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, TIOCSTI, TIOCSTI)));

    // keyring 系
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(keyctl), 0));
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(add_key), 0));
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(request_key), 0));

    // ptrace
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(ptrace), 0));

    // NUMA系
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(mbind), 0));
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(migrate_pages), 0));
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(move_pages), 0));
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0));

    // userfaultfd
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(userfaultfd), 0));

    // perf_event_open
    RULE_FAIL_CHECK(seccomp_rule_add(context, SCMP_FAIL, SCMP_SYS(perf_event_open), 0));

    // PR_SET_NO_NEW_PRIVS → 0
    if (seccomp_attr_set(context, SCMP_FLTATR_CTL_NNP, 0) != 0) {
        perror("seccomp_attr_set(CTL_NNP)");
        seccomp_release(context);
        return NULL;
    }

#undef RULE_FAIL_CHECK

    return context;
}

/**
 * @brief Apply seccomp filter to restrict syscalls.
 * @return 0 on success, -1 on failure
 */
int restrict_syscalls(void) {
    fprintf(stderr, "=> restricting syscalls...\n");

    scmp_filter_ctx secure_context = create_secure_context();
    if (!secure_context) {
        return -1;
    }
    if (seccomp_load(secure_context) < 0) {
        perror("seccomp_load failed");
        seccomp_release(secure_context);
        return -1;
    }
    seccomp_release(secure_context);

    fprintf(stderr, "=> syscalls restricted.\n");
    return 0;
}

//------------------------------------------------------
// 3. Mounts 関連
//------------------------------------------------------

/**
 * @brief pivot_root をシステムコールで呼ぶラッパ
 */
static int pivot_root_syscall(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

/**
 * @brief すべての既存マウントを private にする (MS_PRIVATE + MS_REC)
 */
static bool make_all_mounts_private(void) {
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        perror("mount MS_PRIVATE failed");
        return false;
    }
    return true;
}

/**
 * @brief 一時ディレクトリを作成し、そこに bind mount を行う
 * @return bind先のディレクトリパス(ヒープ上)を返す。失敗時はNULL
 */
static char* create_bind_mount(const char *src_dir) {
    // 1) 一時ディレクトリ作成
    char *bind_dir = strdup("/tmp/tmp.XXXXXX");
    if (!bind_dir) {
        perror("strdup failed");
        return NULL;
    }
    if (!mkdtemp(bind_dir)) {
        perror("mkdtemp failed");
        free(bind_dir);
        return NULL;
    }

    // 2) bind mount
    if (mount(src_dir, bind_dir, NULL, MS_BIND | MS_PRIVATE, NULL) != 0) {
        perror("bind mount failed");
        rmdir(bind_dir);
        free(bind_dir);
        return NULL;
    }
    return bind_dir;
}

/**
 * @brief bindマウント先ディレクトリに oldroot 用ディレクトリを作成
 * @return 作成したサブディレクトリパス(ヒープ上) or NULL
 */
static char* create_inner_mount_dir(const char *bind_dir) {
    // 例: "/tmp/tmp.XXXXXX/oldroot.XXXXXX"
    size_t len = strlen(bind_dir) + 1 + sizeof("oldroot.XXXXXX");
    char *inner_dir = calloc(1, len);
    if (!inner_dir) {
        perror("calloc failed");
        return NULL;
    }
    snprintf(inner_dir, len, "%s/oldroot.XXXXXX", bind_dir);

    if (!mkdtemp(inner_dir)) {
        perror("mkdtemp inner failed");
        free(inner_dir);
        return NULL;
    }
    return inner_dir;
}

/**
 * @brief pivot_root して oldroot をアンマウント＆削除
 */
static bool pivot_and_cleanup(const char *bind_dir, const char *inner_dir) {
    if (pivot_root_syscall(bind_dir, inner_dir) != 0) {
        perror("pivot_root failed");
        return false;
    }

    // old root をアンマウント
    //   inner_dir => "/tmp/tmp.XXXXXX/oldroot.XXXXXX"
    //   basename(inner_dir) => "oldroot.XXXXXX"
    char *old_root_dir = basename((char*)inner_dir);
    char old_root[1024] = "/";
    strncat(old_root, old_root_dir, sizeof(old_root) - 2);

    // ルートを "/" に移動
    if (chdir("/") != 0) {
        perror("chdir / failed");
        return false;
    }
    if (umount2(old_root, MNT_DETACH) != 0) {
        perror("umount2 old_root failed");
        return false;
    }
    if (rmdir(old_root) != 0) {
        perror("rmdir old_root failed");
        return false;
    }

    return true;
}

/**
 * @brief 全体のマウント処理
 * @param config child_config 構造体: mount_dir が使用される
 * @return 0 on success, -1 on failure
 */
int mounts(struct child_config *config) {
    fprintf(stderr, "=> setting up mounts...\n");

    // 1. すべてを private に
    if (!make_all_mounts_private()) {
        return -1;
    }

    // 2. bind mount
    char *bind_dir = create_bind_mount(config->mount_dir);
    if (!bind_dir) {
        return -1;
    }

    // 3. inner mount dir
    char *inner_dir = create_inner_mount_dir(bind_dir);
    if (!inner_dir) {
        rmdir(bind_dir);
        free(bind_dir);
        return -1;
    }

    // 4. pivot_root & cleanup old root
    if (!pivot_and_cleanup(bind_dir, inner_dir)) {
        // 失敗時 => cleanup
        // ここでアンマウントや rmdir するかどうかは状況次第
        free(inner_dir);
        free(bind_dir);
        return -1;
    }

    free(inner_dir);
    // pivot_root成功後、bind_dir は ルート( / )になっているが
    // いまやパスとしては使わないのでメモリだけ解放する
    free(bind_dir);

    fprintf(stderr, "=> mounts done.\n");
    return 0;
}
