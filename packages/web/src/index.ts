/** Public contract version for the WebAuthn adapter. */
export const WEB_CONTRACT_VERSION = 1 as const;

export const WEB_FALLBACK_WARNING_CODE = "WEB_CUSTOM_KEYPAD_LOWER_ASSURANCE" as const;
export const MAX_WEBAUTHN_BINARY_BYTES = 8 * 1024;
export const MAX_WEBAUTHN_CREDENTIALS = 64;
export const MAX_WEBAUTHN_EXTENSION_DEPTH = 4;
export const MAX_WEBAUTHN_EXTENSION_NODES = 256;
export const MAX_WEBAUTHN_EXTENSION_KEYS = 32;
export const MAX_WEBAUTHN_EXTENSION_STRING_LENGTH = 2048;
const MAX_WEBAUTHN_CREDENTIAL_ID_LENGTH = 2048;

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

export type WebAuthnMode = "passkey" | "custom-keypad-fallback";
export type WebAuthnSupportReason =
  | "insecure-context"
  | "public-key-api-unavailable"
  | "credential-api-unavailable";

export type WebAuthnClientErrorCode =
  | "insecure-context"
  | "unsupported"
  | "invalid-options"
  | "invalid-mode"
  | "no-credential"
  | "invalid-credential"
  | "fallback-not-acknowledged";

/** Errors contain stable codes and never include credential bytes or user input. */
export class WebAuthnClientError extends Error {
  readonly code: WebAuthnClientErrorCode;

  constructor(code: WebAuthnClientErrorCode, message: string) {
    super(message);
    this.name = "WebAuthnClientError";
    this.code = code;
  }
}

export interface WebAuthnRelyingParty {
  readonly name: string;
  readonly id?: string;
  readonly icon?: string;
}

export interface WebAuthnUser {
  /** Base64url-encoded user handle supplied by the server. */
  readonly id: string;
  readonly name: string;
  readonly displayName: string;
  readonly icon?: string;
}

export interface WebAuthnCredentialParameter {
  readonly type: "public-key";
  readonly alg: number;
}

export type WebAuthnAuthenticatorTransport = "ble" | "hybrid" | "internal" | "nfc" | "usb";
export type WebAuthnUserVerification = "discouraged" | "preferred" | "required";
export type WebAuthnResidentKey = "discouraged" | "preferred" | "required";
export type WebAuthnHint = "client-device" | "hybrid" | "security-key";

export interface WebAuthnCredentialDescriptorJson {
  readonly type: "public-key";
  /** Base64url-encoded credential ID supplied by the server. */
  readonly id: string;
  readonly transports?: readonly WebAuthnAuthenticatorTransport[];
}

export interface WebAuthnAuthenticatorSelection {
  readonly authenticatorAttachment?: "cross-platform" | "platform";
  readonly residentKey?: WebAuthnResidentKey;
  readonly requireResidentKey?: boolean;
  readonly userVerification?: WebAuthnUserVerification;
}

/** Server JSON for navigator.credentials.create({ publicKey }). */
export interface WebAuthnCreationOptionsJson {
  readonly challenge: string;
  readonly rp: WebAuthnRelyingParty;
  readonly user: WebAuthnUser;
  readonly pubKeyCredParams: readonly WebAuthnCredentialParameter[];
  readonly timeout?: number;
  readonly excludeCredentials?: readonly WebAuthnCredentialDescriptorJson[];
  readonly authenticatorSelection?: WebAuthnAuthenticatorSelection;
  readonly attestation?: "none" | "indirect" | "direct" | "enterprise";
  readonly hints?: readonly WebAuthnHint[];
  readonly extensions?: Readonly<Record<string, unknown>>;
}

/** Server JSON for navigator.credentials.get({ publicKey }). */
export interface WebAuthnRequestOptionsJson {
  readonly challenge: string;
  readonly timeout?: number;
  readonly rpId?: string;
  readonly allowCredentials?: readonly WebAuthnCredentialDescriptorJson[];
  readonly userVerification?: WebAuthnUserVerification;
  readonly hints?: readonly WebAuthnHint[];
  readonly extensions?: Readonly<Record<string, unknown>>;
}

export interface WebAuthnCredentialCreationRequest {
  readonly publicKey: Record<string, unknown>;
}

export interface WebAuthnCredentialRequest {
  readonly publicKey: Record<string, unknown>;
}

export interface WebAuthnRegistrationResponse {
  readonly clientDataJSON: ArrayBuffer;
  readonly attestationObject: ArrayBuffer;
  readonly getTransports?: () => readonly WebAuthnAuthenticatorTransport[];
}

export interface WebAuthnAssertionResponse {
  readonly clientDataJSON: ArrayBuffer;
  readonly authenticatorData: ArrayBuffer;
  readonly signature: ArrayBuffer;
  readonly userHandle: ArrayBuffer | null;
}

export interface WebAuthnCredential {
  readonly id: string;
  readonly rawId: ArrayBuffer;
  readonly type: "public-key";
  readonly response: WebAuthnRegistrationResponse | WebAuthnAssertionResponse;
  readonly authenticatorAttachment?: string | null;
  readonly getClientExtensionResults: () => Record<string, unknown>;
}

/** Narrow seam used by the browser and by deterministic adapter tests. */
export interface WebAuthnCredentialApi {
  readonly create: (options: WebAuthnCredentialCreationRequest) => Promise<WebAuthnCredential | null>;
  readonly get: (options: WebAuthnCredentialRequest) => Promise<WebAuthnCredential | null>;
}

export interface WebAuthnEnvironment {
  readonly isSecureContext: boolean;
  readonly hasPublicKeyCredential: boolean;
  readonly credentials?: WebAuthnCredentialApi;
}

export interface WebAuthnSupport {
  readonly available: boolean;
  readonly reason: WebAuthnSupportReason | undefined;
}

export interface SerializedRegistrationCredential {
  readonly id: string;
  readonly rawId: string;
  readonly type: "public-key";
  readonly response: {
    readonly clientDataJSON: string;
    readonly attestationObject: string;
    readonly transports?: readonly WebAuthnAuthenticatorTransport[];
  };
  readonly authenticatorAttachment?: string | null;
  readonly clientExtensionResults: Record<string, unknown>;
}

export interface SerializedAssertionCredential {
  readonly id: string;
  readonly rawId: string;
  readonly type: "public-key";
  readonly response: {
    readonly clientDataJSON: string;
    readonly authenticatorData: string;
    readonly signature: string;
    readonly userHandle: string | null;
  };
  readonly authenticatorAttachment?: string | null;
  readonly clientExtensionResults: Record<string, unknown>;
}

export interface WebFallbackNotice {
  readonly code: typeof WEB_FALLBACK_WARNING_CODE;
  readonly severity: "warning";
  readonly message: string;
}

const WEB_FALLBACK_NOTICE: WebFallbackNotice = Object.freeze({
  code: WEB_FALLBACK_WARNING_CODE,
  severity: "warning",
  message:
    "A custom web keypad is lower assurance: browser JavaScript can observe its input. Prefer passkeys and require explicit product approval before using this fallback.",
});

function invalidOptions(message = "WebAuthn options are invalid"): never {
  throw new WebAuthnClientError("invalid-options", message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isArrayBuffer(value: unknown): value is ArrayBuffer {
  return value instanceof ArrayBuffer;
}

function bytesOf(value: ArrayBuffer | ArrayBufferView): Uint8Array {
  if (isArrayBuffer(value)) return new Uint8Array(value);
  if (!ArrayBuffer.isView(value)) {
    throw new WebAuthnClientError("invalid-credential", "Binary WebAuthn data is invalid");
  }
  return new Uint8Array(value.buffer as ArrayBuffer, value.byteOffset, value.byteLength);
}

/** Encodes WebAuthn binary data for JSON without padding. */
export function encodeBase64Url(value: ArrayBuffer | ArrayBufferView): string {
  const bytes = bytesOf(value);
  let encoded = "";

  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index];
    if (first === undefined) break;
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    encoded += BASE64URL_ALPHABET[first >> 2];
    encoded += BASE64URL_ALPHABET[((first & 0x03) << 4) | ((second ?? 0) >> 4)];
    if (second !== undefined) {
      encoded += BASE64URL_ALPHABET[((second & 0x0f) << 2) | ((third ?? 0) >> 6)];
    }
    if (third !== undefined) encoded += BASE64URL_ALPHABET[third & 0x3f];
  }

  return encoded;
}

/** Decodes strict, unpadded base64url supplied by a trusted server boundary. */
export function decodeBase64Url(value: string, maxBytes = MAX_WEBAUTHN_BINARY_BYTES): Uint8Array {
  if (typeof value !== "string" || value.length > maxBytes * 2 || !BASE64URL_PATTERN.test(value)) {
    throw new WebAuthnClientError("invalid-options", "Base64url WebAuthn data is invalid");
  }
  if (value.length % 4 === 1) {
    throw new WebAuthnClientError("invalid-options", "Base64url WebAuthn data is invalid");
  }

  const output = new Uint8Array(Math.floor((value.length * 6) / 8));
  let accumulator = 0;
  let bits = 0;
  let outputIndex = 0;
  let lastDigit = 0;

  for (const character of value) {
    const digit = BASE64URL_ALPHABET.indexOf(character);
    if (digit < 0) throw new WebAuthnClientError("invalid-options", "Base64url WebAuthn data is invalid");
    lastDigit = digit;
    accumulator = (accumulator << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      const byte = (accumulator >> bits) & 0xff;
      if (outputIndex >= output.length) {
        throw new WebAuthnClientError("invalid-options", "Base64url WebAuthn data is invalid");
      }
      output[outputIndex] = byte;
      outputIndex += 1;
    }
  }

  if (bits > 0 && (lastDigit & ((1 << bits) - 1)) !== 0) {
    throw new WebAuthnClientError("invalid-options", "Base64url WebAuthn data is not canonical");
  }
  if (output.length > maxBytes) {
    throw new WebAuthnClientError("invalid-options", "WebAuthn binary data is too large");
  }
  return output;
}

function requiredString(value: unknown, field: string, maximum: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    invalidOptions(`WebAuthn ${field} is invalid`);
  }
  return value;
}

function optionalString(value: unknown, field: string, maximum: number): string | undefined {
  if (value === undefined) return undefined;
  return requiredString(value, field, maximum);
}

function binaryOption(value: unknown, field: string): Uint8Array {
  const encoded = requiredString(value, field, MAX_WEBAUTHN_BINARY_BYTES * 2);
  try {
    return decodeBase64Url(encoded);
  } catch {
    invalidOptions(`WebAuthn ${field} is invalid`);
  }
}

function boundedTimeout(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || !Number.isFinite(value) || value < 1 || value > 120_000) {
    invalidOptions("WebAuthn timeout is invalid");
  }
  return value;
}

function toNativeAuthenticatorSelection(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) invalidOptions("WebAuthn authenticatorSelection is invalid");
  const allowed = ["authenticatorAttachment", "residentKey", "requireResidentKey", "userVerification"];
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    invalidOptions("WebAuthn authenticatorSelection is invalid");
  }
  const result: Record<string, unknown> = {};
  if (value.authenticatorAttachment !== undefined) {
    if (value.authenticatorAttachment !== "cross-platform" && value.authenticatorAttachment !== "platform") {
      invalidOptions("WebAuthn authenticatorSelection is invalid");
    }
    result.authenticatorAttachment = value.authenticatorAttachment;
  }
  if (value.residentKey !== undefined) {
    if (![
      "discouraged",
      "preferred",
      "required",
    ].includes(String(value.residentKey))) {
      invalidOptions("WebAuthn authenticatorSelection is invalid");
    }
    result.residentKey = value.residentKey;
  }
  if (value.requireResidentKey !== undefined) {
    if (typeof value.requireResidentKey !== "boolean") {
      invalidOptions("WebAuthn authenticatorSelection is invalid");
    }
    result.requireResidentKey = value.requireResidentKey;
  }
  if (value.userVerification !== undefined) {
    if (!["discouraged", "preferred", "required"].includes(String(value.userVerification))) {
      invalidOptions("WebAuthn authenticatorSelection is invalid");
    }
    result.userVerification = value.userVerification;
  }
  return result;
}

function copyBoundedExtensionValue(
  value: unknown,
  field: string,
  errorCode: Extract<WebAuthnClientErrorCode, "invalid-options" | "invalid-credential">,
  depth: number,
  budget: { nodes: number },
): unknown {
  budget.nodes += 1;
  if (budget.nodes > MAX_WEBAUTHN_EXTENSION_NODES || depth > MAX_WEBAUTHN_EXTENSION_DEPTH) {
    throw new WebAuthnClientError(errorCode, `${field} is too complex`);
  }
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.length > MAX_WEBAUTHN_EXTENSION_STRING_LENGTH) {
      throw new WebAuthnClientError(errorCode, `${field} is too large`);
    }
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new WebAuthnClientError(errorCode, `${field} is invalid`);
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_WEBAUTHN_EXTENSION_KEYS) {
      throw new WebAuthnClientError(errorCode, `${field} is too large`);
    }
    return value.map((entry) => copyBoundedExtensionValue(entry, field, errorCode, depth + 1, budget));
  }
  if (!isRecord(value)) throw new WebAuthnClientError(errorCode, `${field} is invalid`);
  const keys = Object.keys(value);
  if (keys.length > MAX_WEBAUTHN_EXTENSION_KEYS) {
    throw new WebAuthnClientError(errorCode, `${field} has too many keys`);
  }
  const result: Record<string, unknown> = {};
  for (const key of keys) {
    if (
      key.length > 128 ||
      key === "__proto__" ||
      key === "constructor" ||
      key === "prototype"
    ) {
      throw new WebAuthnClientError(errorCode, `${field} has an invalid key`);
    }
    result[key] = copyBoundedExtensionValue(value[key], field, errorCode, depth + 1, budget);
  }
  return result;
}

function copyRecord(
  value: unknown,
  field: string,
  errorCode: Extract<WebAuthnClientErrorCode, "invalid-options" | "invalid-credential">,
): Record<string, unknown> | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new WebAuthnClientError(errorCode, `WebAuthn ${field} is invalid`);
  const result = copyBoundedExtensionValue(value, field, errorCode, 0, { nodes: 0 });
  if (!isRecord(result)) throw new WebAuthnClientError(errorCode, `WebAuthn ${field} is invalid`);
  return result;
}

function encodedCredentialBinary(value: unknown, field: string): string {
  if (!isArrayBuffer(value) || value.byteLength > MAX_WEBAUTHN_BINARY_BYTES) {
    throw new WebAuthnClientError("invalid-credential", `WebAuthn ${field} is too large or invalid`);
  }
  return encodeBase64Url(value);
}

function toNativeDescriptor(value: unknown, field: string): Record<string, unknown> {
  if (!isRecord(value) || value.type !== "public-key") invalidOptions(`WebAuthn ${field} is invalid`);
  const id = binaryOption(value.id, `${field}.id`);
  const transports = value.transports;
  if (transports !== undefined) {
    if (
      !Array.isArray(transports) ||
      transports.length > 5 ||
      transports.some((transport) => !["ble", "hybrid", "internal", "nfc", "usb"].includes(String(transport)))
    ) {
      invalidOptions(`WebAuthn ${field}.transports is invalid`);
    }
  }
  const result: Record<string, unknown> = { type: "public-key", id };
  if (transports !== undefined) result.transports = [...transports];
  return result;
}

function toNativeCredentials(value: unknown, field: string): Record<string, unknown>[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > MAX_WEBAUTHN_CREDENTIALS) invalidOptions(`WebAuthn ${field} is invalid`);
  return value.map((descriptor, index) => toNativeDescriptor(descriptor, `${field}[${index}]`));
}

function toNativeCreationOptions(options: WebAuthnCreationOptionsJson): Record<string, unknown> {
  if (!isRecord(options)) invalidOptions();
  const rp = options.rp;
  const user = options.user;
  if (!isRecord(rp) || !isRecord(user)) invalidOptions();
  if (!Array.isArray(options.pubKeyCredParams) || options.pubKeyCredParams.length === 0 || options.pubKeyCredParams.length > 32) {
    invalidOptions("WebAuthn pubKeyCredParams is invalid");
  }

  const publicKey: Record<string, unknown> = {
    challenge: binaryOption(options.challenge, "challenge"),
    rp: {
      name: requiredString(rp.name, "rp.name", 256),
      ...(optionalString(rp.id, "rp.id", 253) === undefined ? {} : { id: optionalString(rp.id, "rp.id", 253) }),
      ...(optionalString(rp.icon, "rp.icon", 2048) === undefined ? {} : { icon: optionalString(rp.icon, "rp.icon", 2048) }),
    },
    user: {
      id: binaryOption(user.id, "user.id"),
      name: requiredString(user.name, "user.name", 320),
      displayName: requiredString(user.displayName, "user.displayName", 256),
      ...(optionalString(user.icon, "user.icon", 2048) === undefined ? {} : { icon: optionalString(user.icon, "user.icon", 2048) }),
    },
    pubKeyCredParams: options.pubKeyCredParams.map((parameter) => {
      if (!isRecord(parameter) || parameter.type !== "public-key" || !Number.isInteger(parameter.alg)) {
        invalidOptions("WebAuthn pubKeyCredParams is invalid");
      }
      return { type: "public-key", alg: parameter.alg };
    }),
  };

  const timeout = boundedTimeout(options.timeout);
  if (timeout !== undefined) publicKey.timeout = timeout;
  const excludeCredentials = toNativeCredentials(options.excludeCredentials, "excludeCredentials");
  if (excludeCredentials !== undefined) publicKey.excludeCredentials = excludeCredentials;
  if (options.authenticatorSelection !== undefined) {
    publicKey.authenticatorSelection = toNativeAuthenticatorSelection(options.authenticatorSelection);
  }
  if (options.attestation !== undefined) {
    if (!["none", "indirect", "direct", "enterprise"].includes(options.attestation)) {
      invalidOptions("WebAuthn attestation is invalid");
    }
    publicKey.attestation = options.attestation;
  }
  if (options.hints !== undefined) {
    if (!Array.isArray(options.hints) || options.hints.length > 3 || options.hints.some((hint) => !["client-device", "hybrid", "security-key"].includes(hint))) {
      invalidOptions("WebAuthn hints are invalid");
    }
    publicKey.hints = [...options.hints];
  }
  const extensions = copyRecord(options.extensions, "extensions", "invalid-options");
  if (extensions !== undefined) publicKey.extensions = extensions;
  return publicKey;
}

function toNativeRequestOptions(options: WebAuthnRequestOptionsJson): Record<string, unknown> {
  if (!isRecord(options)) invalidOptions();
  const publicKey: Record<string, unknown> = { challenge: binaryOption(options.challenge, "challenge") };
  const timeout = boundedTimeout(options.timeout);
  if (timeout !== undefined) publicKey.timeout = timeout;
  const rpId = optionalString(options.rpId, "rpId", 253);
  if (rpId !== undefined) publicKey.rpId = rpId;
  const allowCredentials = toNativeCredentials(options.allowCredentials, "allowCredentials");
  if (allowCredentials !== undefined) publicKey.allowCredentials = allowCredentials;
  if (options.userVerification !== undefined) {
    if (!["discouraged", "preferred", "required"].includes(options.userVerification)) {
      invalidOptions("WebAuthn userVerification is invalid");
    }
    publicKey.userVerification = options.userVerification;
  }
  if (options.hints !== undefined) {
    if (!Array.isArray(options.hints) || options.hints.length > 3 || options.hints.some((hint) => !["client-device", "hybrid", "security-key"].includes(hint))) {
      invalidOptions("WebAuthn hints are invalid");
    }
    publicKey.hints = [...options.hints];
  }
  const extensions = copyRecord(options.extensions, "extensions", "invalid-options");
  if (extensions !== undefined) publicKey.extensions = extensions;
  return publicKey;
}

function extensionResults(credential: WebAuthnCredential): Record<string, unknown> {
  let value: Record<string, unknown>;
  try {
    value = credential.getClientExtensionResults();
  } catch {
    throw new WebAuthnClientError("invalid-credential", "WebAuthn extension results are invalid");
  }
  if (!isRecord(value)) throw new WebAuthnClientError("invalid-credential", "WebAuthn extension results are invalid");
  return copyRecord(value, "WebAuthn extension results", "invalid-credential")!;
}

function baseCredential(credential: WebAuthnCredential): Pick<SerializedRegistrationCredential, "id" | "rawId" | "type" | "authenticatorAttachment" | "clientExtensionResults"> {
  if (
    typeof credential.id !== "string" ||
    credential.id.length === 0 ||
    credential.id.length > MAX_WEBAUTHN_CREDENTIAL_ID_LENGTH ||
    credential.type !== "public-key" || !isArrayBuffer(credential.rawId)
  ) {
    throw new WebAuthnClientError("invalid-credential", "WebAuthn credential is invalid");
  }
  const result: Pick<SerializedRegistrationCredential, "id" | "rawId" | "type" | "authenticatorAttachment" | "clientExtensionResults"> = {
    id: credential.id,
    rawId: encodedCredentialBinary(credential.rawId, "credential rawId"),
    type: "public-key",
    clientExtensionResults: extensionResults(credential),
  };
  if (
    credential.authenticatorAttachment !== undefined &&
    credential.authenticatorAttachment !== null &&
    credential.authenticatorAttachment !== "platform" &&
    credential.authenticatorAttachment !== "cross-platform"
  ) {
    throw new WebAuthnClientError("invalid-credential", "WebAuthn authenticator attachment is invalid");
  }
  return credential.authenticatorAttachment === undefined
    ? result
    : { ...result, authenticatorAttachment: credential.authenticatorAttachment };
}

/** Converts a browser registration credential into the server's JSON envelope. */
export function serializeRegistrationCredential(credential: WebAuthnCredential): SerializedRegistrationCredential {
  const response = credential.response;
  if (!isRecord(response) || !isArrayBuffer(response.clientDataJSON) || !isArrayBuffer(response.attestationObject)) {
    throw new WebAuthnClientError("invalid-credential", "WebAuthn registration response is invalid");
  }
  const base = baseCredential(credential);
  const serializedResponse: SerializedRegistrationCredential["response"] = {
    clientDataJSON: encodedCredentialBinary(response.clientDataJSON, "clientDataJSON"),
    attestationObject: encodedCredentialBinary(response.attestationObject, "attestationObject"),
  };
  if (typeof response.getTransports === "function") {
    const transports = response.getTransports();
    if (
      !Array.isArray(transports) ||
      transports.length > 5 ||
      transports.some((transport) => !["ble", "hybrid", "internal", "nfc", "usb"].includes(transport))
    ) {
      throw new WebAuthnClientError("invalid-credential", "WebAuthn registration transports are invalid");
    }
    return { ...base, response: { ...serializedResponse, transports: [...transports] } };
  }
  return { ...base, response: serializedResponse };
}

/** Converts a browser assertion credential into the server's JSON envelope. */
export function serializeAssertionCredential(credential: WebAuthnCredential): SerializedAssertionCredential {
  const response = credential.response;
  if (
    !isRecord(response) ||
    !isArrayBuffer(response.clientDataJSON) ||
    !isArrayBuffer(response.authenticatorData) ||
    !isArrayBuffer(response.signature) ||
    !(response.userHandle === null || isArrayBuffer(response.userHandle))
  ) {
    throw new WebAuthnClientError("invalid-credential", "WebAuthn assertion response is invalid");
  }
  const base = baseCredential(credential) as Pick<SerializedAssertionCredential, "id" | "rawId" | "type" | "authenticatorAttachment" | "clientExtensionResults">;
  return {
    ...base,
    response: {
      clientDataJSON: encodedCredentialBinary(response.clientDataJSON, "clientDataJSON"),
      authenticatorData: encodedCredentialBinary(response.authenticatorData, "authenticatorData"),
      signature: encodedCredentialBinary(response.signature, "signature"),
      userHandle: response.userHandle === null ? null : encodedCredentialBinary(response.userHandle, "userHandle"),
    },
  };
}

/** Creates a browser environment lazily; importing this package is safe in Node and SSR. */
export function getDefaultWebAuthnEnvironment(): WebAuthnEnvironment {
  const browser = globalThis as unknown as {
    readonly isSecureContext?: boolean;
    readonly PublicKeyCredential?: unknown;
    readonly navigator?: {
      readonly credentials?: {
        readonly create: (options: unknown) => Promise<unknown>;
        readonly get: (options: unknown) => Promise<unknown>;
      };
    };
  };
  const container = browser.navigator?.credentials;
  const credentials: WebAuthnCredentialApi | undefined =
    container !== undefined &&
    typeof container.create === "function" &&
    typeof container.get === "function"
    ? {
        create: async (options) => (await container.create(options)) as WebAuthnCredential | null,
        get: async (options) => (await container.get(options)) as WebAuthnCredential | null,
      }
    : undefined;
  return {
    isSecureContext: browser.isSecureContext === true,
    hasPublicKeyCredential: typeof browser.PublicKeyCredential === "function",
    ...(credentials === undefined ? {} : { credentials }),
  };
}

export function detectWebAuthnSupport(environment = getDefaultWebAuthnEnvironment()): WebAuthnSupport {
  if (!environment.isSecureContext) return { available: false, reason: "insecure-context" };
  if (!environment.hasPublicKeyCredential) return { available: false, reason: "public-key-api-unavailable" };
  if (environment.credentials === undefined || typeof environment.credentials.create !== "function" || typeof environment.credentials.get !== "function") {
    return { available: false, reason: "credential-api-unavailable" };
  }
  return { available: true, reason: undefined };
}

/** Returns the required product warning for a browser custom-keypad fallback. */
export function getWebFallbackNotice(): WebFallbackNotice {
  return WEB_FALLBACK_NOTICE;
}

/** Enforces passkey preference and requires an explicit acknowledgement for web fallback. */
export function assertWebAuthnMode(
  mode: WebAuthnMode,
  environment = getDefaultWebAuthnEnvironment(),
  lowerAssuranceFallbackAcknowledged = false,
): void {
  if (mode !== "passkey" && mode !== "custom-keypad-fallback") {
    throw new WebAuthnClientError("invalid-mode", "WebAuthn mode is invalid");
  }
  if (mode === "custom-keypad-fallback") {
    if (!lowerAssuranceFallbackAcknowledged) {
      throw new WebAuthnClientError(
        "fallback-not-acknowledged",
        "The lower-assurance web keypad fallback requires explicit acknowledgement",
      );
    }
    return;
  }
  const support = detectWebAuthnSupport(environment);
  if (!support.available) {
    const code = support.reason === "insecure-context" ? "insecure-context" : "unsupported";
    throw new WebAuthnClientError(code, "Passkey WebAuthn is unavailable in this environment");
  }
}

export async function createPasskey(
  options: WebAuthnCreationOptionsJson,
  environment = getDefaultWebAuthnEnvironment(),
): Promise<SerializedRegistrationCredential> {
  assertWebAuthnMode("passkey", environment);
  const credential = await environment.credentials!.create({ publicKey: toNativeCreationOptions(options) });
  if (credential === null) throw new WebAuthnClientError("no-credential", "WebAuthn did not return a credential");
  return serializeRegistrationCredential(credential);
}

export async function getPasskey(
  options: WebAuthnRequestOptionsJson,
  environment = getDefaultWebAuthnEnvironment(),
): Promise<SerializedAssertionCredential> {
  assertWebAuthnMode("passkey", environment);
  const credential = await environment.credentials!.get({ publicKey: toNativeRequestOptions(options) });
  if (credential === null) throw new WebAuthnClientError("no-credential", "WebAuthn did not return a credential");
  return serializeAssertionCredential(credential);
}
