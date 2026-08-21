cmake_minimum_required(VERSION 3.22.1)
project(secure_keypad_jni LANGUAGES C)

add_library(secure_keypad_jni SHARED src/main/cpp/secure_keypad_jni.c)
target_include_directories(secure_keypad_jni PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/main/cpp/include)

if(NOT DEFINED SECURE_KEYPAD_FFI_LIB_DIR)
    set(SECURE_KEYPAD_FFI_LIB_DIR "$ENV{SECURE_KEYPAD_FFI_LIB_DIR}")
endif()
if(NOT SECURE_KEYPAD_FFI_LIB_DIR)
    message(FATAL_ERROR "SECURE_KEYPAD_FFI_LIB_DIR must point to the Rust secure_ffi ABI directory")
endif()
if(NOT EXISTS "${SECURE_KEYPAD_FFI_LIB_DIR}/${ANDROID_ABI}/libsecure_ffi.a")
    message(FATAL_ERROR "missing libsecure_ffi.a for ABI ${ANDROID_ABI} under SECURE_KEYPAD_FFI_LIB_DIR")
endif()

add_library(secure_keypad_ffi STATIC IMPORTED)
set_target_properties(secure_keypad_ffi PROPERTIES
    IMPORTED_LOCATION "${SECURE_KEYPAD_FFI_LIB_DIR}/${ANDROID_ABI}/libsecure_ffi.a")

target_link_libraries(secure_keypad_jni
    secure_keypad_ffi
    log
    android)
