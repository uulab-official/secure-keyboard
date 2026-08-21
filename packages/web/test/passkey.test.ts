import { describe, expect, it } from "vitest";
import {
  MAX_WEBAUTHN_BINARY_BYTES,
  WEB_FALLBACK_WARNING_CODE,
  WebAuthnClientError,
  assertWebAuthnMode,
  createPasskey,
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
