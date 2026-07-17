#ifndef ONIONROUTE_MOBILE_H
#define ONIONROUTE_MOBILE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OR_ABI_MAJOR 1u
#define OR_ABI_MINOR 0u
#define OR_EVENT_DATA_CAPACITY 64u
#define OR_MAX_PACKET_BYTES (128u * 1024u)

typedef uint64_t or_client_handle_t;

enum or_status {
  OR_STATUS_OK = 0,
  OR_STATUS_EMPTY = 1,
  OR_STATUS_INVALID_ARGUMENT = -1,
  OR_STATUS_INVALID_HANDLE = -2,
  OR_STATUS_INCOMPATIBLE_VERSION = -3,
  OR_STATUS_SHUTTING_DOWN = -4,
  OR_STATUS_INVALID_STATE = -5,
  OR_STATUS_BACKPRESSURE = -6,
  OR_STATUS_CANCELLED = -7,
  OR_STATUS_UNAVAILABLE = -8,
  OR_STATUS_PANIC = -127
};

enum or_event_kind {
  OR_EVENT_ABI_NEGOTIATED = 1,
  OR_EVENT_STATE_CHANGED = 2,
  OR_EVENT_PLATFORM_ACTION = 3,
  OR_EVENT_OPERATION = 4,
  OR_EVENT_DIAGNOSTIC = 5,
  OR_EVENT_QUEUE_OVERFLOW = 6
};

enum or_client_state {
  OR_STATE_DISCONNECTED = 0,
  OR_STATE_PREPARING = 1,
  OR_STATE_APPLYING_KILL_SWITCH = 2,
  OR_STATE_BOOTSTRAPPING_TOR = 3,
  OR_STATE_CONNECTED = 4,
  OR_STATE_ROTATING = 5,
  OR_STATE_RECONNECTING = 6,
  OR_STATE_BLOCKED = 7,
  OR_STATE_DISCONNECTING = 8
};

enum or_platform_action {
  OR_ACTION_APPLY_KILL_SWITCH = 1,
  OR_ACTION_START_PROTECTED_CORE = 2,
  OR_ACTION_STOP_PROTECTED_CORE = 3,
  OR_ACTION_REFRESH_TOKEN = 4,
  OR_ACTION_REFRESH_SIGNED_CONFIG = 5
};

enum or_anonymity_mode {
  OR_MODE_STANDARD = 0,
  OR_MODE_ENHANCED = 1,
  OR_MODE_MAXIMUM = 2,
  OR_MODE_DIRECT_TOR = 3
};

enum or_rotation_kind {
  OR_ROTATION_SOFT = 0,
  OR_ROTATION_HARD = 1
};

typedef struct or_create_options {
  uint32_t struct_size;
  uint16_t abi_min_major;
  uint16_t abi_min_minor;
  uint16_t abi_max_major;
  uint16_t abi_max_minor;
  uint32_t event_capacity;
  uint64_t memory_budget_bytes;
} or_create_options_t;

typedef struct or_event {
  uint32_t struct_size;
  uint32_t kind;
  uint64_t sequence;
  uint64_t operation_id;
  int32_t code;
  uint32_t data_len;
  uint64_t value;
  uint8_t data[OR_EVENT_DATA_CAPACITY];
} or_event_t;

int32_t or_client_create(const or_create_options_t *options,
                         or_client_handle_t *out_handle);
int32_t or_client_destroy(or_client_handle_t handle);
int32_t or_client_connect(or_client_handle_t handle,
                          uint64_t *out_operation_id);
int32_t or_client_disconnect(or_client_handle_t handle,
                             uint64_t *out_operation_id);
int32_t or_client_set_tunnel_ready(or_client_handle_t handle, uint8_t ready);
int32_t or_client_set_core_ready(or_client_handle_t handle, uint8_t ready);
int32_t or_client_set_network(or_client_handle_t handle, uint8_t available,
                              uint8_t expensive, uint8_t constrained,
                              uint8_t captive);
int32_t or_client_set_country(or_client_handle_t handle,
                              const uint8_t country[2]);
int32_t or_client_set_anonymity_mode(or_client_handle_t handle, uint32_t mode);
int32_t or_client_rotate(or_client_handle_t handle, uint32_t kind,
                         uint64_t *out_operation_id);
int32_t or_client_request_token_refresh(or_client_handle_t handle,
                                        uint64_t *out_operation_id);
int32_t or_client_request_config_refresh(or_client_handle_t handle,
                                         uint64_t *out_operation_id);
int32_t or_client_cancel(or_client_handle_t handle, uint64_t operation_id);
int32_t or_client_suspend(or_client_handle_t handle, uint64_t monotonic_ms);
int32_t or_client_resume(or_client_handle_t handle, uint64_t monotonic_ms,
                         uint8_t protected_path_healthy);
int32_t or_client_submit_packet(or_client_handle_t handle,
                                const uint8_t *packet, size_t packet_len);
int32_t or_client_poll_event(or_client_handle_t handle, or_event_t *out_event);

#ifdef __cplusplus
}
#endif

#endif

