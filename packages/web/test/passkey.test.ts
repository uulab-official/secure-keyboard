import { describe, expect, it } from "vitest";
import {
  MAX_WEBAUTHN_BINARY_BYTES,
  WEB_FALLBACK_WARNING_CODE,
  WebAuthnClientError,
  assertWebAuthnMode,
  createPasskey,
  createPasskeyController,
  decodeBase64Url,
  detectWebAuthnSupport,
  encodeBase64Url,
  getWebFallbackNotice,
  getPasskey,
  getDefaultWebAuthnEnvironment,
  serializeRegistrationCredential,
  type WebAuthnCredentialApi,
  type WebAuthnEnvironment,
} from "../src/index.js";

function environment(credentials: WebAuthnCredentialApi, overrides: Partial<WebAuthnEnvironment> = {}): WebAuthnEnvironment {
  return {
    isSecureContext: true,
    hasPublicKeyCredential: true,
    credentials,
    ...overrides,
  };
}

const creationOptions = {
  challenge: "AQID",
  rp: { name: "Example" },
  user: { id: "BAUG", name: "user@example.test", displayName: "Example User" },
  pubKeyCredParams: [{ type: "public-key" as const, alg: -7 }],
  authenticatorSelection: { residentKey: "required" as const, userVerification: "required" as const },
};

describe("base64url boundary", () => {
  it("round-trips binary bytes without padding", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 255]);
    const encoded = encodeBase64Url(bytes);

    expect(encoded).toBe("AAEC-vv8_w");
    expect(decodeBase64Url(encoded)).toEqual(bytes);
    expect(encodeBase64Url(new Uint8Array())).toBe("");
  });

  it("rejects malformed or oversized binary input", () => {
    expect(() => decodeBase64Url("not base64")).toThrow(WebAuthnClientError);
    expect(() => decodeBase64Url("A")).toThrow(WebAuthnClientError);
    expect(() => decodeBase64Url("AB")).toThrow(WebAuthnClientError);
    expect(() => decodeBase64Url("AAAA", 2)).toThrow(WebAuthnClientError);
    expect(() => encodeBase64Url(new Uint8Array(MAX_WEBAUTHN_BINARY_BYTES + 1))).toThrow(WebAuthnClientError);
  });

  it("rejects an unbounded or non-integral caller-supplied byte limit", () => {
    expect(() => decodeBase64Url("AA", Infinity)).toThrow(WebAuthnClientError);
    expect(() => decodeBase64Url("AA", MAX_WEBAUTHN_BINARY_BYTES + 1)).toThrow(WebAuthnClientError);
    expect(() => decodeBase64Url("AA", 1.5)).toThrow(WebAuthnClientError);
    expect(() => decodeBase64Url("AA", -1)).toThrow(WebAuthnClientError);
  });

  it("rejects base64url above the decoded bound before allocating an output buffer", () => {
    const oversizedEncodedLength = Math.ceil((MAX_WEBAUTHN_BINARY_BYTES * 8) / 6) + 1;
    const oversized = "A".repeat(oversizedEncodedLength);
    const originalUint8Array = Uint8Array;
    let allocations = 0;
    const trackingUint8Array = new Proxy(originalUint8Array, {
      construct(target, argumentsList, newTarget) {
        allocations += 1;
        return Reflect.construct(target, argumentsList, newTarget);
      },
    });
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, "Uint8Array");

    try {
      Object.defineProperty(globalThis, "Uint8Array", {
        configurable: true,
        value: trackingUint8Array,
      });
      expect(() => decodeBase64Url(oversized)).toThrow(WebAuthnClientError);
      expect(allocations).toBe(0);
    } finally {
      if (descriptor === undefined) {
        Reflect.deleteProperty(globalThis, "Uint8Array");
      } else {
        Object.defineProperty(globalThis, "Uint8Array", descriptor);
      }
    }
  });
});

describe("WebAuthn support and mode policy", () => {
  it("requires a secure context and both credential APIs", () => {
    const supported = detectWebAuthnSupport(environment({ create: async () => null, get: async () => null }));
    expect(supported).toEqual({ available: true, reason: undefined });

    expect(
      detectWebAuthnSupport(
        environment({ create: async () => null, get: async () => null }, { isSecureContext: false }),
      ),
    ).toEqual({ available: false, reason: "insecure-context" });

    expect(
      detectWebAuthnSupport(
        environment({ create: async () => null, get: async () => null }, { credentials: undefined }),
      ),
    ).toEqual({ available: false, reason: "credential-api-unavailable" });
  });

  it("does not advertise the default browser environment when credential methods are missing", () => {
    const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    try {
      Object.defineProperty(globalThis, "navigator", {
        configurable: true,
        value: { credentials: { create: undefined, get: async () => null } },
      });
      expect(getDefaultWebAuthnEnvironment().credentials).toBeUndefined();
    } finally {
      if (originalNavigator === undefined) {
        Reflect.deleteProperty(globalThis, "navigator");
      } else {
        Object.defineProperty(globalThis, "navigator", originalNavigator);
      }
    }
  });

  it("fails closed when default browser environment getters throw", () => {
    const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    try {
      Object.defineProperty(globalThis, "navigator", {
        configurable: true,
        value: new Proxy({}, {
          get() {
            throw new Error("fixture-only-secret");
          },
        }),
      });

      expect(() => getDefaultWebAuthnEnvironment()).not.toThrow();
      expect(getDefaultWebAuthnEnvironment()).toEqual({
        isSecureContext: false,
        hasPublicKeyCredential: false,
      });
    } finally {
      if (originalNavigator === undefined) {
        Reflect.deleteProperty(globalThis, "navigator");
      } else {
        Object.defineProperty(globalThis, "navigator", originalNavigator);
      }
    }
  });

  it("does not silently approve the lower-assurance custom keypad fallback", () => {
    expect(() => assertWebAuthnMode("custom-keypad-fallback")).toThrow(/acknowledgement/i);
    expect(() => assertWebAuthnMode("custom-keypad-fallback", undefined, true)).not.toThrow();
    expect(getWebFallbackNotice()).toMatchObject({
      code: WEB_FALLBACK_WARNING_CODE,
      severity: "warning",
    });
  });

  it("rejects an unknown mode at the runtime boundary", () => {
    expect(() => assertWebAuthnMode("unexpected-mode" as never)).toThrow(
      expect.objectContaining({ code: "invalid-mode" }),
    );
  });

  it("exposes a secret-free state stream for custom passkey UIs", async () => {
    const api: WebAuthnCredentialApi = {
      create: async () => ({
        id: "credential-id",
        rawId: new Uint8Array([9, 8, 7]).buffer,
        type: "public-key",
        response: {
          clientDataJSON: new Uint8Array([1]).buffer,
          attestationObject: new Uint8Array([2]).buffer,
        },
        getClientExtensionResults: () => ({}),
      }),
      get: async () => null,
    };
    const controller = createPasskeyController(environment(api));
    const states: unknown[] = [];
    const unsubscribe = controller.subscribe((state) => states.push(state));

    const result = await controller.createPasskey(creationOptions);

    expect(result.id).toBe("credential-id");
    expect(states).toEqual([
      { phase: "pending", operation: "registration" },
      { phase: "success", operation: "registration" },
    ]);
    expect(controller.getState()).toEqual({ phase: "success", operation: "registration" });
    expect(controller.getState()).not.toHaveProperty("credential");
    unsubscribe();
  });

  it("rejects concurrent passkey operations without changing the pending state", async () => {
    let release: (() => void) | undefined;
    const api: WebAuthnCredentialApi = {
      create: () => new Promise((resolve) => {
        release = () => resolve(null);
      }),
      get: async () => null,
    };
    const controller = createPasskeyController(environment(api));
    const first = controller.createPasskey(creationOptions);

    await expect(controller.getPasskey({ challenge: "AQID" })).rejects.toMatchObject({
      code: "operation-in-progress",
    });
    expect(controller.getState()).toEqual({ phase: "pending", operation: "registration" });

    release?.();
    await expect(first).rejects.toMatchObject({ code: "no-credential" });
    expect(controller.getState()).toEqual({
      phase: "error",
      operation: "registration",
      errorCode: "no-credential",
    });
  });

  it("cancels an in-flight passkey operation without exposing browser error text", async () => {
    let observedSignal: AbortSignal | undefined;
    const api: WebAuthnCredentialApi = {
      create: (options) => new Promise((_, reject) => {
        observedSignal = (options as { signal?: AbortSignal }).signal;
        observedSignal?.addEventListener("abort", () => {
          reject({ name: "AbortError", message: "fixture-only-secret" });
        }, { once: true });
      }),
      get: async () => null,
    };
    const controller = createPasskeyController(environment(api));

    expect(typeof controller.cancel).toBe("function");
    const operation = controller.createPasskey(creationOptions);
    await Promise.resolve();
    controller.cancel();

    await expect(operation).rejects.toMatchObject({ code: "aborted" });
    expect(observedSignal?.aborted).toBe(true);
    expect(controller.getState()).toEqual({
      phase: "error",
      operation: "registration",
      errorCode: "aborted",
    });
  });

  it("normalizes browser API failures without exposing the original error", async () => {
    const secret = "fixture-only-secret";
    const api: WebAuthnCredentialApi = {
      create: async () => {
        throw new Error(secret);
      },
      get: async () => {
        throw new Error(secret);
      },
    };

    await expect(createPasskey(creationOptions, environment(api))).rejects.toMatchObject({
      code: "credential-api-failure",
    });
    await expect(getPasskey({ challenge: "AQID" }, environment(api))).rejects.toMatchObject({
      code: "credential-api-failure",
    });
    await expect(createPasskey(creationOptions, environment(api))).rejects.not.toThrow(secret);
  });
});

describe("passkey registration", () => {
  it("converts server JSON options and serializes only the public-key ceremony result", async () => {
    let request: Record<string, unknown> | undefined;
    const api: WebAuthnCredentialApi = {
      create: async (options) => {
        request = options.publicKey;
        return {
          id: "credential-id",
          rawId: new Uint8Array([9, 8, 7]).buffer,
          type: "public-key",
          response: {
            clientDataJSON: new Uint8Array([1, 2]).buffer,
            attestationObject: new Uint8Array([3, 4, 5]).buffer,
            getTransports: () => ["internal"],
          },
          authenticatorAttachment: "platform",
          getClientExtensionResults: () => ({ credProps: { rk: true } }),
        };
      },
      get: async () => null,
    };

    const result = await createPasskey(creationOptions, environment(api));

    expect(request).toMatchObject({
      rp: { name: "Example" },
      user: { name: "user@example.test", displayName: "Example User" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
    });
    expect(request?.challenge).toBeInstanceOf(Uint8Array);
    expect((request?.challenge as Uint8Array)).toEqual(new Uint8Array([1, 2, 3]));
    expect((request?.user as { id: Uint8Array }).id).toEqual(new Uint8Array([4, 5, 6]));
    expect(result).toEqual({
      id: "credential-id",
      rawId: "CQgH",
      type: "public-key",
      response: {
        clientDataJSON: "AQI",
        attestationObject: "AwQF",
        transports: ["internal"],
      },
      authenticatorAttachment: "platform",
      clientExtensionResults: { credProps: { rk: true } },
    });
  });

  it("fails closed when the browser returns no credential", async () => {
    const api: WebAuthnCredentialApi = { create: async () => null, get: async () => null };

    await expect(createPasskey(creationOptions, environment(api))).rejects.toMatchObject({
      code: "no-credential",
    });
  });

  it("serializes an assertion and never turns its signature into a text secret", async () => {
    let request: Record<string, unknown> | undefined;
    const api: WebAuthnCredentialApi = {
      create: async () => null,
      get: async (options) => {
        request = options.publicKey;
        return {
          id: "credential-id",
          rawId: new Uint8Array([9, 8, 7]).buffer,
          type: "public-key",
          response: {
            clientDataJSON: new Uint8Array([1]).buffer,
            authenticatorData: new Uint8Array([2, 3]).buffer,
            signature: new Uint8Array([4, 5, 6]).buffer,
            userHandle: new Uint8Array([7, 8]).buffer,
          },
          getClientExtensionResults: () => ({}),
        };
      },
    };

    const result = await getPasskey(
      {
        challenge: "CQkJ",
        rpId: "example.test",
        allowCredentials: [{ type: "public-key", id: "AQI", transports: ["internal"] }],
        userVerification: "required",
      },
      environment(api),
    );

    expect((request?.challenge as Uint8Array)).toEqual(new Uint8Array([9, 9, 9]));
    expect((request?.allowCredentials as Array<{ id: Uint8Array }>)[0]?.id).toEqual(new Uint8Array([1, 2]));
    expect(result.response).toEqual({
      clientDataJSON: "AQ",
      authenticatorData: "AgM",
      signature: "BAUG",
      userHandle: "Bwg",
    });
  });

  it("rejects malformed browser credentials without exposing response data", () => {
    expect(() =>
      serializeRegistrationCredential({
        id: "credential-id",
        rawId: new ArrayBuffer(0),
        type: "public-key",
        response: { clientDataJSON: new ArrayBuffer(1) } as never,
        getClientExtensionResults: () => ({}),
      }),
    ).toThrow(/registration response is invalid/);
  });

  it("normalizes hostile credential getters without exposing their error", () => {
    const credential = new Proxy(
      {
        id: "credential-id",
        rawId: new Uint8Array([1]).buffer,
        type: "public-key" as const,
        response: {
          clientDataJSON: new ArrayBuffer(1),
          attestationObject: new ArrayBuffer(1),
        },
        getClientExtensionResults: () => ({}),
      },
      {
        get(target, property, receiver) {
          if (property === "id") throw new Error("fixture-only-secret");
          return Reflect.get(target, property, receiver);
        },
      },
    );

    expect(() => serializeRegistrationCredential(credential as never)).toThrow(
      expect.objectContaining({ code: "invalid-credential" }),
    );
    expect(() => serializeRegistrationCredential(credential as never)).toThrow(
      expect.not.stringContaining("fixture-only-secret"),
    );
  });

  it("bounds server extension JSON before handing it to the browser", async () => {
    await expect(
      createPasskey(
        { ...creationOptions, extensions: { oversized: "x".repeat(2049) } },
        environment({ create: async () => null, get: async () => null }),
      ),
    ).rejects.toMatchObject({ code: "invalid-options" });
  });

  it("whitelists authenticator selection fields before handing them to the browser", async () => {
    await expect(
      createPasskey(
        {
          ...creationOptions,
          authenticatorSelection: { residentKey: "required", unexpected: "ignored" } as never,
        },
        environment({ create: async () => null, get: async () => null }),
      ),
    ).rejects.toMatchObject({ code: "invalid-options" });
  });

  it("rejects prototype-pollution keys in server extension JSON", async () => {
    const extensions = JSON.parse('{"__proto__":{"polluted":true}}');

    await expect(
      createPasskey(
        { ...creationOptions, extensions },
        environment({ create: async () => null, get: async () => null }),
      ),
    ).rejects.toMatchObject({ code: "invalid-options" });
  });

  it("bounds browser extension results before serializing them", async () => {
    const api: WebAuthnCredentialApi = {
      create: async () => ({
        id: "credential-id",
        rawId: new Uint8Array([1]).buffer,
        type: "public-key",
        response: {
          clientDataJSON: new Uint8Array([1]).buffer,
          attestationObject: new Uint8Array([2]).buffer,
        },
        getClientExtensionResults: () => ({ oversized: "x".repeat(2049) }),
      }),
      get: async () => null,
    };

    await expect(createPasskey(creationOptions, environment(api))).rejects.toMatchObject({
      code: "invalid-credential",
    });
  });

  it("bounds browser credential binary data and validates attachment metadata", () => {
    const oversizedRawId = new Uint8Array(MAX_WEBAUTHN_BINARY_BYTES + 1).buffer;
    expect(() =>
      serializeRegistrationCredential({
        id: "credential-id",
        rawId: oversizedRawId,
        type: "public-key",
        response: {
          clientDataJSON: new ArrayBuffer(1),
          attestationObject: new ArrayBuffer(1),
        },
        getClientExtensionResults: () => ({}),
      }),
    ).toThrow(/too large/);

    expect(() =>
      serializeRegistrationCredential({
        id: "credential-id",
        rawId: new ArrayBuffer(1),
        type: "public-key",
        response: {
          clientDataJSON: new ArrayBuffer(1),
          attestationObject: new ArrayBuffer(1),
        },
        authenticatorAttachment: { unexpected: true } as never,
        getClientExtensionResults: () => ({}),
      }),
    ).toThrow(/attachment/);
  });
});
