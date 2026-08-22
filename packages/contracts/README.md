# @secure-keypad/contracts

Versioned, secret-free layout, theme, masked-state, and event contracts for secure keypad renderers.

Layouts may set `randomizeInputKeys: true` to request native CSPRNG shuffling of
input-role key positions. The option carries no seed or secret and does not
apply to action keys.

This package intentionally does not expose a password value, accumulated input, or value callback. Use it with a Secure Native renderer for the highest mobile assurance.
