#include <jni.h>
#include <stdint.h>
#include <string.h>

#include "onionroute_mobile.h"

JNIEXPORT jlong JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeCreate(
    JNIEnv *env, jobject self, jint event_capacity, jlong memory_budget) {
  (void)env;
  (void)self;
  or_create_options_t options = {
      .struct_size = sizeof(or_create_options_t),
      .abi_min_major = OR_ABI_MAJOR,
      .abi_min_minor = OR_ABI_MINOR,
      .abi_max_major = OR_ABI_MAJOR,
      .abi_max_minor = OR_ABI_MINOR,
      .event_capacity = (uint32_t)event_capacity,
      .memory_budget_bytes = (uint64_t)memory_budget,
  };
  or_client_handle_t handle = 0;
  return or_client_create(&options, &handle) == OR_STATUS_OK ? (jlong)handle : 0;
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeDestroy(
    JNIEnv *env, jobject self, jlong handle) {
  (void)env;
  (void)self;
  return or_client_destroy((or_client_handle_t)handle);
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeConnect(
    JNIEnv *env, jobject self, jlong handle) {
  (void)env;
  (void)self;
  uint64_t operation = 0;
  return or_client_connect((or_client_handle_t)handle, &operation);
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeDisconnect(
    JNIEnv *env, jobject self, jlong handle) {
  (void)env;
  (void)self;
  uint64_t operation = 0;
  return or_client_disconnect((or_client_handle_t)handle, &operation);
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeSetTunnelReady(
    JNIEnv *env, jobject self, jlong handle, jboolean ready) {
  (void)env;
  (void)self;
  return or_client_set_tunnel_ready((or_client_handle_t)handle, ready ? 1 : 0);
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeSetNetwork(
    JNIEnv *env, jobject self, jlong handle, jboolean available,
    jboolean expensive, jboolean constrained, jboolean captive) {
  (void)env;
  (void)self;
  return or_client_set_network((or_client_handle_t)handle, available ? 1 : 0,
                               expensive ? 1 : 0, constrained ? 1 : 0,
                               captive ? 1 : 0);
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeSetCountry(
    JNIEnv *env, jobject self, jlong handle, jbyteArray country) {
  (void)self;
  if (country == NULL || (*env)->GetArrayLength(env, country) != 2) {
    return OR_STATUS_INVALID_ARGUMENT;
  }
  jbyte bytes[2];
  (*env)->GetByteArrayRegion(env, country, 0, 2, bytes);
  return or_client_set_country((or_client_handle_t)handle,
                               (const uint8_t *)bytes);
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeSetMode(
    JNIEnv *env, jobject self, jlong handle, jint mode) {
  (void)env;
  (void)self;
  return or_client_set_anonymity_mode((or_client_handle_t)handle,
                                      (uint32_t)mode);
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeRotate(
    JNIEnv *env, jobject self, jlong handle, jboolean hard) {
  (void)env;
  (void)self;
  uint64_t operation = 0;
  return or_client_rotate((or_client_handle_t)handle, hard ? 1 : 0,
                          &operation);
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeRequestTokenRefresh(
    JNIEnv *env, jobject self, jlong handle) {
  (void)env;
  (void)self;
  uint64_t operation = 0;
  return or_client_request_token_refresh((or_client_handle_t)handle, &operation);
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeRequestConfigRefresh(
    JNIEnv *env, jobject self, jlong handle) {
  (void)env;
  (void)self;
  uint64_t operation = 0;
  return or_client_request_config_refresh((or_client_handle_t)handle, &operation);
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeSuspend(
    JNIEnv *env, jobject self, jlong handle, jlong monotonic_ms) {
  (void)env;
  (void)self;
  return or_client_suspend((or_client_handle_t)handle,
                           (uint64_t)monotonic_ms);
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeResume(
    JNIEnv *env, jobject self, jlong handle, jlong monotonic_ms,
    jboolean healthy) {
  (void)env;
  (void)self;
  return or_client_resume((or_client_handle_t)handle,
                          (uint64_t)monotonic_ms, healthy ? 1 : 0);
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativeSubmitPacket(
    JNIEnv *env, jobject self, jlong handle, jbyteArray packet, jint length) {
  (void)self;
  if (packet == NULL || length <= 0 ||
      length > (*env)->GetArrayLength(env, packet)) {
    return OR_STATUS_INVALID_ARGUMENT;
  }
  jbyte *bytes = (*env)->GetByteArrayElements(env, packet, NULL);
  if (bytes == NULL) {
    return OR_STATUS_BACKPRESSURE;
  }
  int32_t status = or_client_submit_packet(
      (or_client_handle_t)handle, (const uint8_t *)bytes, (size_t)length);
  (*env)->ReleaseByteArrayElements(env, packet, bytes, JNI_ABORT);
  return status;
}

JNIEXPORT jint JNICALL
Java_org_onionroute_mobile_core_NativeCore_nativePollEvent(
    JNIEnv *env, jobject self, jlong handle, jlongArray fields,
    jbyteArray data) {
  (void)self;
  if (fields == NULL || data == NULL ||
      (*env)->GetArrayLength(env, fields) < 6 ||
      (*env)->GetArrayLength(env, data) < OR_EVENT_DATA_CAPACITY) {
    return OR_STATUS_INVALID_ARGUMENT;
  }
  or_event_t event;
  memset(&event, 0, sizeof(event));
  event.struct_size = sizeof(event);
  int32_t status = or_client_poll_event((or_client_handle_t)handle, &event);
  if (status != OR_STATUS_OK) {
    return status;
  }
  jlong values[6] = {(jlong)event.kind,
                     (jlong)event.sequence,
                     (jlong)event.operation_id,
                     (jlong)event.code,
                     (jlong)event.value,
                     (jlong)event.data_len};
  (*env)->SetLongArrayRegion(env, fields, 0, 6, values);
  if (event.data_len > 0) {
    (*env)->SetByteArrayRegion(env, data, 0, (jsize)event.data_len,
                              (const jbyte *)event.data);
  }
  return OR_STATUS_OK;
}
