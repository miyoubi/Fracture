#ifndef KEYMASTER_DEVICE_STATE_H
#define KEYMASTER_DEVICE_STATE_H

#include <stddef.h>
#include <stdint.h>

int keymaster_device_state_main(int argc, char **argv);
int keymaster_device_state_validate(const unsigned char *data, size_t length,
                                    uint8_t unlocked, uint8_t unlock_critical);
int keymaster_device_state_save_backup(const char *path,
                                       const unsigned char *data,
                                       size_t length);

#endif
