import {
  createPasskeyController,
  type PasskeyPresentationState,
  type WebAuthnCreationOptionsJson,
} from "@secure-keypad/web";

export interface PasskeyUi {
  readonly getState: () => PasskeyPresentationState;
  readonly subscribe: (listener: (state: PasskeyPresentationState) => void) => () => void;
  readonly register: () => Promise<void>;
  readonly cancel: () => void;
}

async function readCreationOptions(endpoint: string): Promise<WebAuthnCreationOptionsJson> {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { accept: "application/json" },
    credentials: "same-origin",
  });
  if (!response.ok) throw new Error("passkey options request failed");
  return (await response.json()) as WebAuthnCreationOptionsJson;
}

/**
 * Connects a public passkey lifecycle UI to server ceremony endpoints.
 * Credential response data is sent directly to the server and is not placed
 * in UI state, browser storage, logs, or framework props.
 */
export function createPasskeyUi(
  optionsEndpoint = "/api/passkeys/registration/options",
  finishEndpoint = "/api/passkeys/registration/finish",
): PasskeyUi {
  const controller = createPasskeyController();

  return {
    getState: controller.getState,
    subscribe: controller.subscribe,
    register: async () => {
      const options = await readCreationOptions(optionsEndpoint);
      const credential = await controller.createPasskey(options);
      const response = await fetch(finishEndpoint, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(credential),
      });
      if (!response.ok) throw new Error("passkey registration failed");
    },
    cancel: () => controller.cancel(),
  };
}
