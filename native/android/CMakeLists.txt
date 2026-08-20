cmake_minimum_required(VERSION 3.22.1)
project(secure_keypad_jni LANGUAGES C)

add_library(secure_keypad_jni SHARED src/main/cpp/secure_keypad_jni.c)
target_include_directories(secure_keypad_jni PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../../crates/secure-ffi/include)

# The Android app supplies the Rust secure-ffi static library for its ABI and
# links the platform system libraries required by Rust. This CMake target only
# owns the JNI adapter; it never implements or copies secret state.
