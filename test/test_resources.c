#include <stdio.h>
#include <string.h>
#include "../include/container.h"
#include "../include/resources.h"

/*
 * 簡易テスト：
 *  - resources() が -1 を返さないか？
 *  - free_resources() が -1 を返さないか？
 * などを確認
 */

// 仮の child_config
static struct child_config dummy_config = {
    .uid       = 1000,
    .argc      = 1,
    .fd        = 0,
    .hostname  = "testhostname",
    .argv      = NULL,
    .mount_dir = "/"
};

int test_resources(void) {
    // ここでは実際に /sys/fs/cgroup/... への書き込みができるかは
    // 環境依存なので、一旦呼び出してエラーが出ないか程度を見る例
    if (resources(&dummy_config) != 0) {
        fprintf(stderr, "resources() returned error\n");
        return 1;
    }
    if (free_resources(&dummy_config) != 0) {
        fprintf(stderr, "free_resources() returned error\n");
        return 1;
    }
    return 0;
}
