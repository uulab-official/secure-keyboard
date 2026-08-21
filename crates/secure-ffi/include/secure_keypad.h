#ifndef SECURE_KEYPAD_H
#define SECURE_KEYPAD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SECURE_KEYPAD_ABI_VERSION UINT32_C(1)

typedef struct secure_keypad_session secure_keypad_session_t;
typedef struct secure_keypad_submission secure_keypad_submission_t;
typedef struct secure_keypad_auth_message secure_keypad_auth_message_t;
typedef struct secure_keypad_client_login secure_keypad_client_login_t;

typedef uint32_t secure_keypad_error_t;
#define SECURE_KEYPAD_OK UINT32_C(0)
#define SECURE_KEYPAD_INVALID_ARGUMENT UINT32_C(1)
#define SECURE_KEYPAD_INVALID_UTF8 UINT32_C(2)
#define SECURE_KEYPAD_INVALID_KEY UINT32_C(3)
#define SECURE_KEYPAD_LIMIT_REACHED UINT32_C(4)
#define SECURE_KEYPAD_EMPTY UINT32_C(5)
#define SECURE_KEYPAD_INACTIVE UINT32_C(6)
#define SECURE_KEYPAD_INTERNAL UINT32_C(7)
#define SECURE_KEYPAD_MESSAGE_TOO_LARGE UINT32_C(8)
#define SECURE_KEYPAD_BUFFER_TOO_SMALL UINT32_C(9)
#define SECURE_KEYPAD_AUTH_PROTOCOL UINT32_C(10)
#define SECURE_KEYPAD_AUTH_INVALID_LOGIN UINT32_C(11)
#define SECURE_KEYPAD_PANIC UINT32_C(255)

typedef uint32_t secure_keypad_display_state_t;
#define SECURE_KEYPAD_DISPLAY_EMPTY UINT32_C(0)
#define SECURE_KEYPAD_DISPLAY_MASKED UINT32_C(1)
#define SECURE_KEYPAD_DISPLAY_SUBMITTED UINT32_C(2)
#define SECURE_KEYPAD_DISPLAY_CANCELLED UINT32_C(3)

typedef struct secure_keypad_masked_state {
    uint32_t length;
    secure_keypad_display_state_t display_state;
} secure_keypad_masked_state_t;

/*
 * No function in this header returns accumulated secret bytes. The submission
 * handle is native-owned and must be passed to a native authentication layer
 * or released with secure_keypad_submission_free(). Handles are single-owner
 * and must not be used concurrently.
 */

secure_keypad_error_t secure_keypad_session_new_numeric(
    uint32_t max_tokens,
    uint64_t timeout_ms,
    secure_keypad_session_t **output);

secure_keypad_error_t secure_keypad_session_new_hangul(
    uint32_t max_tokens,
    uint64_t timeout_ms,
    secure_keypad_session_t **output);

void secure_keypad_session_free(secure_keypad_session_t *session);
void secure_keypad_submission_free(secure_keypad_submission_t *submission);
void secure_keypad_auth_message_free(secure_keypad_auth_message_t *message);
void secure_keypad_client_login_free(secure_keypad_client_login_t *login);

secure_keypad_error_t secure_keypad_session_press_key(
    secure_keypad_session_t *session,
    const uint8_t *key_id,
    size_t key_id_len);

secure_keypad_error_t secure_keypad_session_backspace(
    secure_keypad_session_t *session);

secure_keypad_error_t secure_keypad_session_clear(
    secure_keypad_session_t *session);

secure_keypad_error_t secure_keypad_session_cancel(
    secure_keypad_session_t *session);

secure_keypad_error_t secure_keypad_session_refresh(
    secure_keypad_session_t *session,
    secure_keypad_masked_state_t *output);

secure_keypad_error_t secure_keypad_session_submit(
    secure_keypad_session_t *session,
    secure_keypad_submission_t **output);

/* Native-only OPAQUE message transport. These functions never expose a
 * password or a derived client session key to the caller. */
secure_keypad_error_t secure_keypad_auth_message_new(
    const uint8_t *bytes,
    size_t length,
    secure_keypad_auth_message_t **output);

secure_keypad_error_t secure_keypad_auth_message_size(
    const secure_keypad_auth_message_t *message,
    size_t *output_length);

secure_keypad_error_t secure_keypad_auth_message_copy(
    const secure_keypad_auth_message_t *message,
    uint8_t *output,
    size_t output_length,
    size_t *output_written);

secure_keypad_error_t secure_keypad_client_login_start(
    secure_keypad_submission_t **submission,
    secure_keypad_client_login_t **output_login,
    secure_keypad_auth_message_t **output_request);

secure_keypad_error_t secure_keypad_client_login_finish(
    secure_keypad_client_login_t **login,
    const secure_keypad_auth_message_t *response,
    const uint8_t *client_identifier,
    size_t client_identifier_len,
    const uint8_t *server_identifier,
    size_t server_identifier_len,
    secure_keypad_auth_message_t **output_finalization);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_KEYPAD_H */
