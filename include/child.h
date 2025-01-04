#ifndef CHILD_H
#define CHILD_H

#include "container.h"

// 子プロセスの実装 (cloneで呼び出す関数)
int child(void *arg);

#endif
