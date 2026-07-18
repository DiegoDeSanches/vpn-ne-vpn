#include "onionroute_mobile.h"

/* Clang imports plain C enums as distinct Swift wrapper types. Keep these
 * fixed-width conversions in the iOS adapter so the shared C ABI is unchanged. */
static inline int32_t or_ios_status_value(enum or_status value) {
  return (int32_t)value;
}

static inline uint32_t
or_ios_packet_protocol_value(enum or_packet_protocol value) {
  return (uint32_t)value;
}

static inline uint32_t
or_ios_rotation_kind_value(enum or_rotation_kind value) {
  return (uint32_t)value;
}
