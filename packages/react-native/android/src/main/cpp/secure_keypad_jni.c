#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

#include "secure_keypad.h"

static secure_keypad_session_t *session_from_handle(jlong handle) {
    return (secure_keypad_session_t *)(uintptr_t)handle;
}

static secure_keypad_submission_t *submission_from_handle(jlong handle) {
    return (secure_keypad_submission_t *)(uintptr_t)handle;
}

JNIEXPORT jint JNICALL
Java_com_uulab_securekeypad_SecureKeypadNative_nativeAbiVersion(
    JNIEnv *env, jobject object) {
    (void)env;
    (void)object;
    return (jint)secure_keypad_abi_version();
}

JNIEXPORT jlong JNICALL
Java_com_uulab_securekeypad_SecureKeypadNative_nativeSessionNewNumeric(
    JNIEnv *env, jobject object, jint max_tokens, jlong timeout_ms) {
    (void)env;
    (void)object;
    secure_keypad_session_t *session = NULL;
    secure_keypad_error_t error = secure_keypad_session_new_numeric(
        (uint32_t)max_tokens, (uint64_t)timeout_ms, &session);
    return error == SECURE_KEYPAD_OK ? (jlong)(uintptr_t)session : 0;
}

JNIEXPORT jlong JNICALL
Java_com_uulab_securekeypad_SecureKeypadNative_nativeSessionNewAscii(
    JNIEnv *env, jobject object, jint max_tokens, jlong timeout_ms) {
    (void)env;
    (void)object;
    secure_keypad_session_t *session = NULL;
    secure_keypad_error_t error = secure_keypad_session_new_ascii(
        (uint32_t)max_tokens, (uint64_t)timeout_ms, &session);
    return error == SECURE_KEYPAD_OK ? (jlong)(uintptr_t)session : 0;
}

JNIEXPORT jlong JNICALL
Java_com_uulab_securekeypad_SecureKeypadNative_nativeSessionNewHangul(
    JNIEnv *env, jobject object, jint max_tokens, jlong timeout_ms) {
    (void)env;
    (void)object;
    secure_keypad_session_t *session = NULL;
    secure_keypad_error_t error = secure_keypad_session_new_hangul(
        (uint32_t)max_tokens, (uint64_t)timeout_ms, &session);
    return error == SECURE_KEYPAD_OK ? (jlong)(uintptr_t)session : 0;
}

JNIEXPORT void JNICALL
Java_com_uulab_securekeypad_SecureKeypadNative_nativeSessionFree(
    JNIEnv *env, jobject object, jlong handle) {
    (void)env;
    (void)object;
    secure_keypad_session_free(session_from_handle(handle));
}

JNIEXPORT jint JNICALL
Java_com_uulab_securekeypad_SecureKeypadNative_nativeSessionPressKey(
    JNIEnv *env, jobject object, jlong handle, jbyteArray key_id) {
    (void)object;
    if (key_id == NULL) return SECURE_KEYPAD_INVALID_ARGUMENT;
    jsize length = (*env)->GetArrayLength(env, key_id);
    jbyte *bytes = (*env)->GetByteArrayElements(env, key_id, NULL);
    if (bytes == NULL) return SECURE_KEYPAD_INVALID_ARGUMENT;
    secure_keypad_error_t error = secure_keypad_session_press_key(
        session_from_handle(handle), (const uint8_t *)bytes, (size_t)length);
    (*env)->ReleaseByteArrayElements(env, key_id, bytes, JNI_ABORT);
    return (jint)error;
}

JNIEXPORT jint JNICALL
Java_com_uulab_securekeypad_SecureKeypadNative_nativeSessionBackspace(
    JNIEnv *env, jobject object, jlong handle) {
    (void)env;
    (void)object;
    return (jint)secure_keypad_session_backspace(session_from_handle(handle));
}

JNIEXPORT jint JNICALL
Java_com_uulab_securekeypad_SecureKeypadNative_nativeSessionClear(
    JNIEnv *env, jobject object, jlong handle) {
    (void)env;
    (void)object;
    return (jint)secure_keypad_session_clear(session_from_handle(handle));
}

JNIEXPORT jint JNICALL
Java_com_uulab_securekeypad_SecureKeypadNative_nativeSessionCancel(
    JNIEnv *env, jobject object, jlong handle) {
    (void)env;
    (void)object;
    return (jint)secure_keypad_session_cancel(session_from_handle(handle));
}

JNIEXPORT jlong JNICALL
Java_com_uulab_securekeypad_SecureKeypadNative_nativeSessionRefresh(
    JNIEnv *env, jobject object, jlong handle) {
    (void)env;
    (void)object;
    secure_keypad_masked_state_t state = {0, SECURE_KEYPAD_DISPLAY_EMPTY};
    secure_keypad_error_t error = secure_keypad_session_refresh(
        session_from_handle(handle), &state);
    if (error != SECURE_KEYPAD_OK) return (jlong)INT64_MIN;
    return ((jlong)state.length << 32) | (jlong)state.display_state;
}

JNIEXPORT jlong JNICALL
Java_com_uulab_securekeypad_SecureKeypadNative_nativeSessionSubmit(
    JNIEnv *env, jobject object, jlong handle) {
    (void)env;
    (void)object;
    secure_keypad_submission_t *submission = NULL;
    secure_keypad_error_t error = secure_keypad_session_submit(
        session_from_handle(handle), &submission);
    return error == SECURE_KEYPAD_OK ? (jlong)(uintptr_t)submission : 0;
}

JNIEXPORT void JNICALL
Java_com_uulab_securekeypad_SecureKeypadNative_nativeSubmissionFree(
    JNIEnv *env, jobject object, jlong handle) {
    (void)env;
    (void)object;
    secure_keypad_submission_free(submission_from_handle(handle));
}
