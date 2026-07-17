cmake_minimum_required(VERSION 3.22.1)
project(onionroute_jni C)

set(ONIONROUTE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../..")

add_library(onionroute_mobile_ffi STATIC IMPORTED)
set_target_properties(onionroute_mobile_ffi PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/../rust/${ANDROID_ABI}/libonionroute_mobile_ffi.a")

add_library(onionroute_jni SHARED onionroute_jni.c)
target_include_directories(onionroute_jni PRIVATE
    "${ONIONROUTE_ROOT}/crates/mobile-ffi/include")
target_link_libraries(onionroute_jni onionroute_mobile_ffi log android)

