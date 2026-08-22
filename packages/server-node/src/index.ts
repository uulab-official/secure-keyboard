/** Version of the Node/TypeScript server transport contract. */
export const NODE_SERVER_CONTRACT_VERSION = 1 as const;

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
  readonly body: string | Uint8Array;
}

/**
 * A host-supplied bridge to the reference OPAQUE route.
 *
 * This adapter intentionally does not implement OPAQUE in JavaScript. The
 * delegate must call the pinned Rust/native reference service and return only
 * the generic HTTP response contract. It must never log or persist `body`.
 */
export type OpaqueRouteDelegate = (
  request: NodeHttpRequest,
  context: NodeDeploymentContext,
) => NodeHttpResponse | Promise<NodeHttpResponse>;

export interface CreateOpaqueHandlerOptions {
  readonly deploymentContext: NodeDeploymentContext;
  /** Host session/origin validation; it runs before `Request.body` is read. */
  readonly csrfValidated: (request: Request) => boolean | Promise<boolean>;
  readonly delegate: OpaqueRouteDelegate;
}

const STATUS_CODES = new Set([200, 400, 401, 403, 404, 405, 413, 415, 503]);
const encoder = new TextEncoder();

class BodyTooLargeError extends Error {}

function errorBody(code: "invalid_request" | "temporarily_unavailable"): Uint8Array {
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

function genericResponse(status: number, code: "invalid_request" | "temporarily_unavailable"): Response {
  return new Response(responseBody(errorBody(code)), { status, headers: responseHeaders() });
}

function isReady(context: NodeDeploymentContext): boolean {
  return (
    (context.transport === "direct-tls" || context.transport === "trusted-proxy-tls") &&
    Number.isSafeInteger(context.upstreamBodyLimitBytes) &&
    context.upstreamBodyLimitBytes > 0 &&
    context.upstreamBodyLimitBytes <= MAX_HTTP_BODY_BYTES &&
    context.connectionLimitsEnforced
  );
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
      const chunk = result.value;
      const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
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
  if (!STATUS_CODES.has(value.status)) return genericResponse(503, "temporarily_unavailable");
  const body = typeof value.body === "string" ? encoder.encode(value.body) : value.body;
  if (!(body instanceof Uint8Array) || body.byteLength > MAX_HTTP_BODY_BYTES) {
    return genericResponse(503, "temporarily_unavailable");
  }
  return new Response(responseBody(body), { status: value.status, headers: responseHeaders() });
}

/**
 * Creates a Web Fetch-compatible Node server handler for the reference
 * OPAQUE HTTP contract.
 *
 * The handler validates deployment, route, media type, CSRF, and the byte
 * bound before reading the body. It does not inspect forwarded headers or
 * parse authentication JSON; the delegate remains the version-pinned
 * cryptographic boundary. The bounded request buffer is cleared immediately
 * after delegation, but copies made by the host runtime or delegate cannot be
 * controlled by this adapter.
 */
export function createOpaqueHandler(options: CreateOpaqueHandlerOptions): (request: Request) => Promise<Response> {
  return async (request) => {
    if (!isReady(options.deploymentContext)) return genericResponse(400, "invalid_request");

    const path = routePath(request);
    if (path === undefined) return genericResponse(404, "invalid_request");
    if (request.method !== "POST") return genericResponse(405, "invalid_request");
    if (!isJsonContentType(request.headers.get("content-type"))) {
      return genericResponse(415, "invalid_request");
    }

    let csrfPassed = false;
    try {
      csrfPassed = await options.csrfValidated(request);
    } catch {
      return genericResponse(503, "temporarily_unavailable");
    }
    if (!csrfPassed) return genericResponse(403, "invalid_request");

    const declaredLength = declaredBodyLength(request);
    if (declaredLength === "invalid") return genericResponse(400, "invalid_request");
    if (declaredLength !== undefined && declaredLength > options.deploymentContext.upstreamBodyLimitBytes) {
      return genericResponse(413, "invalid_request");
    }

    let body: Uint8Array;
    try {
      body = await readBoundedBody(request, options.deploymentContext.upstreamBodyLimitBytes);
    } catch (error) {
      if (error instanceof BodyTooLargeError) return genericResponse(413, "invalid_request");
      return genericResponse(503, "temporarily_unavailable");
    }

    try {
      const response = await options.delegate(
        {
          method: "POST",
          path,
          contentType: request.headers.get("content-type") ?? JSON_CONTENT_TYPE,
          csrfValidated: true,
          body,
        },
        options.deploymentContext,
      );
      return responseFromDelegate(response);
    } catch {
      return genericResponse(503, "temporarily_unavailable");
    } finally {
      body.fill(0);
    }
  };
}
