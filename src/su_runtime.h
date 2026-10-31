#ifndef SU_RUNTIME_H
#define SU_RUNTIME_H

#include <sys/types.h>

int su_runtime_dispatch(int argc, char **argv);
int su_runtime_prepare(void);
void su_runtime_close_prepared_server_socket(void);
int su_runtime_wait_ready(int timeout_ms);
int su_runtime_start_daemon(volatile int *stage);

#endif
