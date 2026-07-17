#ifndef OnionRoute_RustBridge_h
#define OnionRoute_RustBridge_h

#include <stdint.h>
#include <stddef.h>

// Generated from the reviewed Rust FFI adapter. No UI target links this header.
int32_t onionroute_core_start(void);
void onionroute_core_stop(void);
int32_t onionroute_core_ingest_packet(const uint8_t *bytes, size_t length, int32_t protocol_family);
int32_t onionroute_daemon_handle_ipc(const uint8_t *request, size_t request_length,
                                     uint8_t *response, size_t response_capacity,
                                     size_t *response_length);

#endif

