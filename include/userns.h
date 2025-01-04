#ifndef USERNS_H
#define USERNS_H

#include <sys/types.h>
#include "container.h"

int handle_child_uid_map(pid_t child_pid, int fd);
int userns(struct child_config *config);

#endif
