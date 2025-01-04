#ifndef RESOURCES_H
#define RESOURCES_H

#include "container.h"

// cgroupsとrlimitの設定
int resources(struct child_config *config);

// 終了時に cgroup を片付ける
int free_resources(struct child_config *config);

#endif
