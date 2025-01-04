#include <stdio.h>

// テスト用ヘッダ
int test_resources(void);

int main(void) {
    int fail_count = 0;

    fprintf(stderr, "[TEST] test_resources...\n");
    if (test_resources() != 0) {
        fprintf(stderr, "[FAIL] test_resources\n");
        fail_count++;
    } else {
        fprintf(stderr, "[OK] test_resources\n");
    }

    if (fail_count == 0) {
        fprintf(stderr, "All tests passed.\n");
    } else {
        fprintf(stderr, "%d tests failed.\n", fail_count);
    }
    return fail_count ? 1 : 0;
}
