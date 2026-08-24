/** Must match `secure_auth_http::HTTP_CONTRACT_VERSION` in the Rust route. */
export const NODE_SERVER_CONTRACT_VERSION = 1 as const;
/** Must match `secure_auth::PROTOCOL_VERSION` in the pinned Rust delegate. */
export const OPAQUE_PROTOCOL_VERSION = 1 as const;
/** Must match `secure_auth::CIPHER_SUITE_ID` in the pinned Rust delegate. */
export const OPAQUE_CIPHER_SUITE_ID = "opaque-ke-4.0.1-ristretto255-tripledh-sha512-argon2" as const;

/** Maximum raw JSON body accepted before the host OPAQUE delegate runs. */
export const MAX_HTTP_BODY_BYTES = 128 * 1024;
/** JSON media type emitted by every response. */
export const JSON_CONTENT_TYPE = "application/json; charset=utf-8";

/** Exact OPAQUE HTTP paths implemented by the Rust reference route. */
export const OPAQUE_ROUTE_PATHS = Object.freeze([
  "/v1/opaque/registration/start",
  "/v1/opaque/registration/finish",
  "/v1/opaque/login/start",
  "/v1/opaque/login/finish",
] as const);

/** Headers that the host must preserve on every authentication response. */
export const RESPONSE_SECURITY_HEADERS = Object.freeze([
  Object.freeze({ name: "cache-control", value: "no-store" }),
  Object.freeze({ name: "pragma", value: "no-cache" }),
  Object.freeze({ name: "x-content-type-options", value: "nosniff" }),
  Object.freeze({ name: "referrer-policy", value: "no-referrer" }),
  Object.freeze({
    name: "content-security-policy",
    value: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  }),
] as const);

export type NodeTransportSecurity = "direct-tls" | "trusted-proxy-tls" | "plaintext";

/** Server admission profile. Financial mode requires verified device integrity. */
export type NodeSecurityProfile = "standard" | "financial";

/** Result of host-side Play Integrity/App Attest or equivalent verification. */
export type NodeDeviceIntegrityDecision = "verified" | "rejected" | "unavailable";

export type NodeFinancialAuthOperation = "registration" | "login";

export type NodeDeviceIntegrityProvider =
  | "android-play-integrity"
  | "ios-app-attest"
  | "ios-device-check"
  | "custom";

/** Host-derived public binding that the attestation must cover. */
export interface NodeFinancialAuthContext {
  readonly subject: string;
  readonly operation: NodeFinancialAuthOperation;
  readonly nonce: string;
  readonly deploymentId: string;
}

/** Verified evidence returned only after the host checks the vendor token. */
export interface NodeDeviceIntegrityEvidence extends NodeFinancialAuthContext {
  readonly provider: NodeDeviceIntegrityProvider;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

/** Host-side admission result returned before the request body is read. */
export type NodeRateLimitDecision = "allowed" | "rate-limited" | "unavailable";

/** Deployment facts validated by the host before request-body buffering. */
export interface NodeDeploymentContext {
  readonly transport: NodeTransportSecurity;
  readonly upstreamBodyLimitBytes: number;
  readonly connectionLimitsEnforced: boolean;
}

/** The bounded request view passed to the Rust/native OPAQUE bridge. */
export interface NodeHttpRequest {
  readonly method: "POST";
  readonly path: (typeof OPAQUE_ROUTE_PATHS)[number];
  readonly contentType: string;
  readonly csrfValidated: true;
  readonly body: Uint8Array;
}

/** Generic response returned by the OPAQUE bridge. */
export interface NodeHttpResponse {
  readonly status: number;
  /** Response bytes are copied into the Fetch response and then zeroized. */
  readonly body: Uint8Array;
}

/**
 * A host-supplied bridge to the reference OPAQUE route.
 *
 * This adapter intentionally does not implement OPAQUE in JavaScript. The
 * delegate must call the pinned Rust/native reference service and return only
 * the generic HTTP response contract. It must never log or persist `body`.
 * The delegate must finish consuming `body` before it returns; the adapter
 * clears that buffer immediately after the returned response is materialized.
 */
export type OpaqueRouteDelegate = (
  request: NodeHttpRequest,
  context: NodeDeploymentContext,
) => NodeHttpResponse | Promise<NodeHttpResponse>;

export type NodeFinancialContextResolver = (
  request: Request,
  path: (typeof OPAQUE_ROUTE_PATHS)[number],
) => NodeFinancialAuthContext | undefined | Promise<NodeFinancialAuthContext | undefined>;

export type NodeDeviceIntegrityVerifier = (
  request: Request,
  context: NodeFinancialAuthContext,
) => NodeDeviceIntegrityEvidence | NodeDeviceIntegrityDecision | Promise<NodeDeviceIntegrityEvidence | NodeDeviceIntegrityDecision>;

export interface CreateOpaqueHandlerOptions {
  readonly deploymentContext: NodeDeploymentContext;
  /** Financial profile fails closed unless this host verifier returns verified. */
  readonly securityProfile?: NodeSecurityProfile;
  /** Resolves the account/operation/nonce binding before Request.body is read. */
  readonly financialContext?: NodeFinancialContextResolver;
  /** Host-side platform attestation verifier; it runs before Request.body is read. */
  readonly deviceIntegrityVerifier?: NodeDeviceIntegrityVerifier;
  /** Host session/origin validation; it runs before `Request.body` is read. */
  readonly csrfValidated: (request: Request) => boolean | Promise<boolean>;
  /**
   * Host account/IP/deployment rate-limit admission; it runs before
   * `Request.body` is read. Omitting this callback fails closed with a generic
   * temporary-unavailability response.
   */
  readonly rateLimitDecision?: (
    request: Request,
  ) => NodeRateLimitDecision | Promise<NodeRateLimitDecision>;
  readonly delegate: OpaqueRouteDelegate;
}

const STATUS_CODES = new Set([200, 400, 401, 403, 404, 405, 413, 415, 429, 503]);
const encoder = new TextEncoder();
const MAX_FINANCIAL_REPLAY_ENTRIES = 4096;

class BodyTooLargeError extends Error {}

function isSecurityProfile(value: unknown): value is NodeSecurityProfile {
  return value === "standard" || value === "financial";
}

const DEVICE_INTEGRITY_PROVIDERS = new Set<NodeDeviceIntegrityProvider>([
  "android-play-integrity",
  "ios-app-attest",
  "ios-device-check",
  "custom",
]);

function isBoundedBinding(value: unknown, minimumLength: number, maximumLength: number): value is string {
  return typeof value === "string" &&
    value.length >= minimumLength &&
    value.length <= maximumLength &&
    !/[\u0000-\u0020\u007f]/.test(value);
}

function isValidFinancialContext(
  value: unknown,
  path: (typeof OPAQUE_ROUTE_PATHS)[number],
): value is NodeFinancialAuthContext {
  const candidate = value as Partial<NodeFinancialAuthContext> | null;
  if (candidate === null || typeof candidate !== "object") return false;
  const operation = path.includes("registration") ? "registration" : "login";
  return candidate.operation === operation &&
    isBoundedBinding(candidate.subject, 1, 256) &&
    isBoundedBinding(candidate.nonce, 16, 512) &&
    isBoundedBinding(candidate.deploymentId, 1, 128);
}

function isFreshBoundEvidence(
  value: unknown,
  context: NodeFinancialAuthContext,
  nowMs = Date.now(),
): value is NodeDeviceIntegrityEvidence {
  const candidate = value as Partial<NodeDeviceIntegrityEvidence> | null;
  if (candidate === null || typeof candidate !== "object") return false;
  if (!DEVICE_INTEGRITY_PROVIDERS.has(candidate.provider as NodeDeviceIntegrityProvider)) return false;
  if (candidate.subject !== context.subject ||
      candidate.operation !== context.operation ||
      candidate.nonce !== context.nonce ||
      candidate.deploymentId !== context.deploymentId) return false;
  if (!Number.isSafeInteger(candidate.issuedAtMs) || !Number.isSafeInteger(candidate.expiresAtMs)) return false;
  const issuedAtMs = candidate.issuedAtMs as number;
  const expiresAtMs = candidate.expiresAtMs as number;
  return issuedAtMs <= nowMs + 30_000 &&
    expiresAtMs > nowMs &&
    expiresAtMs > issuedAtMs &&
    expiresAtMs - issuedAtMs <= 300_000;
}

type FinancialReplayDecision = "consumed" | "replayed" | "unavailable";

function consumeFinancialEvidence(
  consumedEvidence: Map<string, number>,
  context: NodeFinancialAuthContext,
  expiresAtMs: number,
  nowMs = Date.now(),
): FinancialReplayDecision {
  try {
    for (const [key, expiresAt] of consumedEvidence) {
      if (expiresAt <= nowMs) consumedEvidence.delete(key);
    }
    const replayKey = `${context.deploymentId}\u0000${context.subject}\u0000${context.operation}\u0000${context.nonce}`;
    if (consumedEvidence.has(replayKey)) return "replayed";
    if (consumedEvidence.size >= MAX_FINANCIAL_REPLAY_ENTRIES) return "unavailable";
    consumedEvidence.set(replayKey, expiresAtMs);
    return "consumed";
  } catch {
    return "unavailable";
  }
}

function isBodyTooLargeError(error: unknown): boolean {
  try {
    return error instanceof BodyTooLargeError;
  } catch {
    return false;
  }
}

function errorBody(code: "invalid_request" | "rate_limited" | "temporarily_unavailable"): Uint8Array {
  return encoder.encode(JSON.stringify({ error: code }));
}

function responseBody(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}

function responseHeaders(): Headers {
  const headers = new Headers({ "content-type": JSON_CONTENT_TYPE });
  for (const header of RESPONSE_SECURITY_HEADERS) headers.set(header.name, header.value);
  return headers;
}

function byteView(value: unknown): Uint8Array | undefined {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    const bytesPerElement = (value as ArrayBufferView & { BYTES_PER_ELEMENT?: unknown }).BYTES_PER_ELEMENT;
    if (bytesPerElement !== 1) return undefined;
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return undefined;
}

function zeroizeChunk(value: unknown): void {
  if (ArrayBuffer.isView(value)) {
    new Uint8Array(value.buffer, value.byteOffset, value.byteLength).fill(0);
  } else if (value instanceof ArrayBuffer) {
    new Uint8Array(value).fill(0);
  }
}

function genericResponse(
  status: number,
  code: "invalid_request" | "rate_limited" | "temporarily_unavailable",
): Response {
  return new Response(responseBody(errorBody(code)), { status, headers: responseHeaders() });
}

function isReady(context: NodeDeploymentContext): number | undefined {
  try {
    if (
      (context.transport === "direct-tls" || context.transport === "trusted-proxy-tls") &&
      Number.isSafeInteger(context.upstreamBodyLimitBytes) &&
      context.upstreamBodyLimitBytes > 0 &&
      context.upstreamBodyLimitBytes <= MAX_HTTP_BODY_BYTES &&
      context.connectionLimitsEnforced
    ) {
      return context.upstreamBodyLimitBytes;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

function routePath(request: Request): (typeof OPAQUE_ROUTE_PATHS)[number] | undefined {
  try {
    const url = new URL(request.url);
    if (url.search || url.hash) return undefined;
    return (OPAQUE_ROUTE_PATHS as readonly string[]).includes(url.pathname)
      ? (url.pathname as (typeof OPAQUE_ROUTE_PATHS)[number])
      : undefined;
  } catch {
    return undefined;
  }
}

function isJsonContentType(value: string | null): value is string {
  const mediaType = value?.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/json";
}

function declaredBodyLength(request: Request): number | "invalid" | undefined {
  const value = request.headers.get("content-length");
  if (value === null) return undefined;
  if (!/^\d+$/.test(value.trim())) return "invalid";
  const length = Number(value);
  return Number.isSafeInteger(length) ? length : "invalid";
}

async function readBoundedBody(request: Request, limit: number): Promise<Uint8Array> {
  if (request.body === null) return new Uint8Array();

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  const clearChunks = (): void => {
    for (const chunk of chunks) chunk.fill(0);
  };
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      const bytes = byteView(result.value);
      if (bytes === undefined) {
        zeroizeChunk(result.value);
        try {
          await reader.cancel();
        } catch {
          // The malformed chunk remains authoritative even if cleanup fails.
        }
        clearChunks();
        throw new TypeError("request stream yielded a non-byte chunk");
      }
      total += bytes.byteLength;
      if (total > limit) {
        try {
          await reader.cancel();
        } catch {
          // The size violation remains authoritative even if transport cleanup fails.
        }
        clearChunks();
        throw new BodyTooLargeError();
      }
      chunks.push(bytes);
    }
  } catch (error) {
    clearChunks();
    throw error;
  } finally {
    reader.releaseLock();
  }

  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  clearChunks();
  return output;
}

function responseFromDelegate(value: NodeHttpResponse): Response {
  const candidate = value as unknown as { readonly status?: unknown; readonly body?: unknown } | null;
  const body = candidate !== null && typeof candidate === "object" ? candidate.body : undefined;
  try {
    if (candidate === null || typeof candidate.status !== "number" || !STATUS_CODES.has(candidate.status)) {
      return genericResponse(503, "temporarily_unavailable");
    }
    if (!(body instanceof Uint8Array) || body.byteLength > MAX_HTTP_BODY_BYTES) {
      return genericResponse(503, "temporarily_unavailable");
    }
    return new Response(responseBody(body), { status: candidate.status, headers: responseHeaders() });
  } finally {
    zeroizeChunk(body);
  }
}

/**
 * Creates a Web Fetch-compatible Node server handler for the reference
 * OPAQUE HTTP contract.
 *
 * The handler validates deployment, route, media type, CSRF, rate-limit
 * admission, and the byte bound before reading the body. It does not inspect
 * forwarded headers or parse authentication JSON; the delegate remains the
 * version-pinned cryptographic boundary. The bounded request buffer is cleared
 * immediately after delegation, but copies made by the host runtime or
 * delegate cannot be controlled by this adapter.
 */
export function createOpaqueHandler(options: CreateOpaqueHandlerOptions): (request: Request) => Promise<Response> {
  const consumedFinancialEvidence = new Map<string, number>();
  return async (request) => {
    let handlerOptions: CreateOpaqueHandlerOptions;
    try {
      const rateLimitDecision = options.rateLimitDecision;
      const financialContext = options.financialContext;
      const deviceIntegrityVerifier = options.deviceIntegrityVerifier;
      handlerOptions = {
        deploymentContext: options.deploymentContext,
        securityProfile: options.securityProfile ?? "standard",
        csrfValidated: options.csrfValidated,
        delegate: options.delegate,
        ...(financialContext === undefined ? {} : { financialContext }),
        ...(deviceIntegrityVerifier === undefined ? {} : { deviceIntegrityVerifier }),
        ...(rateLimitDecision === undefined ? {} : { rateLimitDecision }),
      };
    } catch {
      return genericResponse(503, "temporarily_unavailable");
    }
    const {
      deploymentContext,
      securityProfile,
      financialContext,
      deviceIntegrityVerifier,
      csrfValidated,
      rateLimitDecision,
      delegate,
    } = handlerOptions;
    if (!isSecurityProfile(securityProfile)) return genericResponse(400, "invalid_request");
    const upstreamBodyLimitBytes = isReady(deploymentContext);
    if (upstreamBodyLimitBytes === undefined) return genericResponse(400, "invalid_request");

    let path: (typeof OPAQUE_ROUTE_PATHS)[number] | undefined;
    let contentType: string | null;
    try {
      path = routePath(request);
      if (path === undefined) return genericResponse(404, "invalid_request");
      if (request.method !== "POST") return genericResponse(405, "invalid_request");
      contentType = request.headers.get("content-type");
      if (!isJsonContentType(contentType)) {
        return genericResponse(415, "invalid_request");
      }
      const declaredLength = declaredBodyLength(request);
      if (declaredLength === "invalid") return genericResponse(400, "invalid_request");
      if (declaredLength !== undefined && declaredLength > upstreamBodyLimitBytes) {
        return genericResponse(413, "invalid_request");
      }
    } catch {
      return genericResponse(503, "temporarily_unavailable");
    }

    let csrfPassed = false;
    try {
      csrfPassed = await csrfValidated(request);
    } catch {
      return genericResponse(503, "temporarily_unavailable");
    }
    if (!csrfPassed) return genericResponse(403, "invalid_request");

    if (rateLimitDecision === undefined) {
      return genericResponse(503, "temporarily_unavailable");
    }
    let rateLimitResult: NodeRateLimitDecision;
    try {
      rateLimitResult = await rateLimitDecision(request);
    } catch {
      return genericResponse(503, "temporarily_unavailable");
    }
    if (rateLimitResult === "rate-limited") return genericResponse(429, "rate_limited");
    if (rateLimitResult !== "allowed") return genericResponse(503, "temporarily_unavailable");

    if (securityProfile === "financial") {
      if (financialContext === undefined || deviceIntegrityVerifier === undefined || path === undefined) {
        return genericResponse(503, "temporarily_unavailable");
      }
      let context: NodeFinancialAuthContext | undefined;
      try {
        context = await financialContext(request, path);
      } catch {
        return genericResponse(503, "temporarily_unavailable");
      }
      try {
        if (!isValidFinancialContext(context, path)) return genericResponse(503, "temporarily_unavailable");
      } catch {
        return genericResponse(503, "temporarily_unavailable");
      }

      let verification: NodeDeviceIntegrityEvidence | NodeDeviceIntegrityDecision;
      try {
        verification = await deviceIntegrityVerifier(request, context);
      } catch {
        return genericResponse(503, "temporarily_unavailable");
      }
      if (verification === "rejected") return genericResponse(403, "invalid_request");
      if (verification === "unavailable" || verification === "verified") {
        return genericResponse(503, "temporarily_unavailable");
      }
      let evidenceIsValid = false;
      try {
        evidenceIsValid = isFreshBoundEvidence(verification, context);
      } catch {
        return genericResponse(503, "temporarily_unavailable");
      }
      if (!evidenceIsValid) {
        return genericResponse(403, "invalid_request");
      }
      const replayDecision = consumeFinancialEvidence(
        consumedFinancialEvidence,
        context,
        verification.expiresAtMs,
      );
      if (replayDecision === "replayed") return genericResponse(403, "invalid_request");
      if (replayDecision !== "consumed") return genericResponse(503, "temporarily_unavailable");
    }

    let body: Uint8Array;
    try {
      body = await readBoundedBody(request, upstreamBodyLimitBytes);
    } catch (error) {
      if (isBodyTooLargeError(error)) return genericResponse(413, "invalid_request");
      return genericResponse(503, "temporarily_unavailable");
    }

    try {
      const response = await delegate(
        {
          method: "POST",
          path,
          contentType: contentType ?? JSON_CONTENT_TYPE,
          csrfValidated: true,
          body,
        },
        deploymentContext,
      );
      return responseFromDelegate(response);
    } catch {
      return genericResponse(503, "temporarily_unavailable");
    } finally {
      body.fill(0);
    }
  };
}
