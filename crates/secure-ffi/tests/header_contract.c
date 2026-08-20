#include "secure_keypad.h"

_Static_assert(sizeof(secure_keypad_error_t) == sizeof(uint32_t), "error ABI must be u32");
_Static_assert(sizeof(secure_keypad_display_state_t) == sizeof(uint32_t), "state ABI must be u32");
_Static_assert(sizeof(secure_keypad_masked_state_t) == sizeof(uint32_t) * 2, "masked state ABI changed");

int main(void) {
    secure_keypad_session_t *session = 0;
    secure_keypad_submission_t *submission = 0;
    secure_keypad_masked_state_t state = {0, SECURE_KEYPAD_DISPLAY_EMPTY};

    (void)secure_keypad_session_new_numeric(4, 60000, &session);
    (void)secure_keypad_session_press_key(session, (const uint8_t *)"digit-1", 7);
    (void)secure_keypad_session_refresh(session, &state);
    (void)secure_keypad_session_submit(session, &submission);
    secure_keypad_submission_free(submission);
    secure_keypad_session_free(session);
    return 0;
}
