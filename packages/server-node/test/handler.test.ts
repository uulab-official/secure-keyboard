import { describe, expect, it, vi } from "vitest";
import {
  JSON_CONTENT_TYPE,
  MAX_HTTP_BODY_BYTES,
  RESPONSE_SECURITY_HEADERS,
  createOpaqueHandler,
  type CreateOpaqueHandlerOptions,
  type NodeDeploymentContext,
  type NodeHttpRequest,
} from "../src/index.js";

const secureContext: NodeDeploymentContext = {
  transport: "direct-tls",
  upstreamBodyLimitBytes: MAX_HTTP_BODY_BYTES,
  connectionLimitsEnforced: true,
};

function request(body: BodyInit | null = null, headers: HeadersInit = {}, url = "https://auth.example.test/v1/opaque/login/start") {
  return new Request(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
}

describe("Node OPAQUE HTTP adapter", () => {
  it("rejects a rate-limited request before reading the body", async () => {
    const delegate = vi.fn();
    const rateLimitDecision = vi.fn(() => "rate-limited");
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision,
      delegate,
    });
    const incoming = request('{"protocolVersion":1}');

    const response = await handler(incoming);

    expect(response.status).toBe(429);
    expect(await response.text()).toBe('{"error":"rate_limited"}');
    expect(rateLimitDecision).toHaveBeenCalledWith(incoming);
    expect(incoming.bodyUsed).toBe(false);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("fails closed when rate-limit admission is unavailable or missing", async () => {
    const delegate = vi.fn();
    const unavailable = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "unavailable",
      delegate,
    });
    const missing = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      delegate,
    });

    const unavailableResponse = await unavailable(request("{}"));
    const missingResponse = await missing(request("{}"));

    expect(unavailableResponse.status).toBe(503);
    expect(missingResponse.status).toBe(503);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("requires bound device integrity evidence for financial profile", async () => {
    const delegate = vi.fn();
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      securityProfile: "financial",
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate,
    });
    const incoming = request('{"protocolVersion":1}');

    const response = await handler(incoming);

    expect(response.status).toBe(503);
    expect(await response.text()).toBe('{"error":"temporarily_unavailable"}');
    expect(incoming.bodyUsed).toBe(false);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("rejects a failed financial device integrity decision before reading the body", async () => {
    const delegate = vi.fn();
    const deviceIntegrityVerifier = vi.fn(() => "rejected" as const);
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      securityProfile: "financial",
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      financialContext: () => ({
        subject: "user-123",
        operation: "login",
        nonce: "nonce-1234567890",
        deploymentId: "prod-kor-1",
      }),
      deviceIntegrityVerifier,
      delegate,
    });
    const incoming = request('{"protocolVersion":1}');

    const response = await handler(incoming);

    expect(response.status).toBe(403);
    expect(await response.text()).toBe('{"error":"invalid_request"}');
    expect(deviceIntegrityVerifier).toHaveBeenCalledWith(incoming, {
      subject: "user-123",
      operation: "login",
      nonce: "nonce-1234567890",
      deploymentId: "prod-kor-1",
    });
    expect(incoming.bodyUsed).toBe(false);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("delegates a financial request only after device integrity is verified", async () => {
    const delegate = vi.fn(() => ({ status: 200, body: new TextEncoder().encode('{"ok":true}') }));
    const now = Date.now();
    const context = {
      subject: "user-123",
      operation: "login" as const,
      nonce: "nonce-1234567890",
      deploymentId: "prod-kor-1",
    };
    const financialContext = vi.fn(() => context);
    const deviceIntegrityVerifier = vi.fn((_request, verifiedContext) => ({
      ...verifiedContext,
      provider: "android-play-integrity" as const,
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
    }));
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      securityProfile: "financial",
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      financialContext,
      deviceIntegrityVerifier,
      delegate,
    });
    const incoming = request('{"protocolVersion":1}');

    const response = await handler(incoming);

    expect(response.status).toBe(200);
    expect(financialContext).toHaveBeenCalledWith(incoming, "/v1/opaque/login/start");
    expect(deviceIntegrityVerifier).toHaveBeenCalledWith(incoming, context);
    expect(delegate).toHaveBeenCalledOnce();
  });

  it("rejects financial evidence whose nonce does not match the host context", async () => {
    const now = Date.now();
    const delegate = vi.fn();
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      securityProfile: "financial",
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      financialContext: () => ({
        subject: "user-123",
        operation: "login" as const,
        nonce: "nonce-1234567890",
        deploymentId: "prod-kor-1",
      }),
      deviceIntegrityVerifier: () => ({
        subject: "user-123",
        operation: "login" as const,
        nonce: "nonce-wrong-1234",
        deploymentId: "prod-kor-1",
        provider: "ios-app-attest" as const,
        issuedAtMs: now - 1_000,
        expiresAtMs: now + 60_000,
      }),
      delegate,
    });
    const incoming = request('{"protocolVersion":1}');

    const response = await handler(incoming);

    expect(response.status).toBe(403);
    expect(incoming.bodyUsed).toBe(false);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("rejects expired financial device integrity evidence before delegation", async () => {
    const now = Date.now();
    const delegate = vi.fn();
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      securityProfile: "financial",
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      financialContext: () => ({
        subject: "user-123",
        operation: "login" as const,
        nonce: "nonce-1234567890",
        deploymentId: "prod-kor-1",
      }),
      deviceIntegrityVerifier: () => ({
        subject: "user-123",
        operation: "login" as const,
        nonce: "nonce-1234567890",
        deploymentId: "prod-kor-1",
        provider: "ios-device-check" as const,
        issuedAtMs: now - 120_000,
        expiresAtMs: now - 60_000,
      }),
      delegate,
    });
    const incoming = request('{"protocolVersion":1}');

    const response = await handler(incoming);

    expect(response.status).toBe(403);
    expect(incoming.bodyUsed).toBe(false);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("applies the financial binding limit to UTF-8 bytes", async () => {
    const delegate = vi.fn();
    const deviceIntegrityVerifier = vi.fn();
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      securityProfile: "financial",
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      financialContext: () => ({
        subject: "한".repeat(129),
        operation: "login" as const,
        nonce: "nonce-1234567890",
        deploymentId: "prod-kor-1",
      }),
      deviceIntegrityVerifier,
      delegate,
    });
    const incoming = request("{}");

    const response = await handler(incoming);

    expect(response.status).toBe(503);
    expect(incoming.bodyUsed).toBe(false);
    expect(deviceIntegrityVerifier).not.toHaveBeenCalled();
    expect(delegate).not.toHaveBeenCalled();
  });

  it("rejects reuse of the same financial evidence within one handler", async () => {
    const now = Date.now();
    const context = {
      subject: "user-123",
      operation: "login" as const,
      nonce: "nonce-replay-123456",
      deploymentId: "prod-kor-1",
    };
    const delegate = vi.fn(() => ({ status: 200, body: new Uint8Array() }));
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      securityProfile: "financial",
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      financialContext: () => context,
      deviceIntegrityVerifier: () => ({
        ...context,
        provider: "custom" as const,
        issuedAtMs: now - 1_000,
        expiresAtMs: now + 60_000,
      }),
      delegate,
    });

    const firstResponse = await handler(request("{}"));
    const replayRequest = request("{}");
    const replayResponse = await handler(replayRequest);

    expect(firstResponse.status).toBe(200);
    expect(replayResponse.status).toBe(403);
    expect(replayRequest.bodyUsed).toBe(false);
    expect(delegate).toHaveBeenCalledOnce();
  });

  it("normalizes rate-limit callback failures and invalid decisions before body access", async () => {
    const delegate = vi.fn();
    const callbackFailure = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => {
        throw new Error("secret-bearing limiter failure");
      },
      delegate,
    });
    const invalidDecision = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "unexpected" as never,
      delegate,
    });
    const callbackRequest = request("{}");
    const invalidRequest = request("{}");

    const callbackResponse = await callbackFailure(callbackRequest);
    const invalidResponse = await invalidDecision(invalidRequest);

    expect(callbackResponse.status).toBe(503);
    expect(invalidResponse.status).toBe(503);
    expect(callbackRequest.bodyUsed).toBe(false);
    expect(invalidRequest.bodyUsed).toBe(false);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("fails closed when deployment context accessors throw hostile errors", async () => {
    const secret = "fixture-only-secret";
    const hostileError = new Proxy(
      {},
      {
        getPrototypeOf: () => {
          throw new Error(secret);
        },
      },
    );
    const hostileContext = new Proxy(
      {},
      {
        get: () => {
          throw hostileError;
        },
      },
    ) as NodeDeploymentContext;
    const delegate = vi.fn();
    const handler = createOpaqueHandler({
      deploymentContext: hostileContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate,
    });

    const response = await handler(request("{}"));

    expect(response.status).toBe(400);
    await expect(response.text()).resolves.not.toContain(secret);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("normalizes hostile request metadata accessors without exposing their traps", async () => {
    const secret = "fixture-only-secret";
    const hostileError = new Proxy(
      {},
      {
        getPrototypeOf: () => {
          throw new Error(secret);
        },
      },
    );
    const incoming = new Proxy(
      {
        url: "https://auth.example.test/v1/opaque/login/start",
        body: null,
      },
      {
        get(target, property, receiver) {
          if (property === "method") throw hostileError;
          return Reflect.get(target, property, receiver);
        },
      },
    ) as unknown as Request;
    const delegate = vi.fn();
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate,
    });

    const response = await handler(incoming);

    expect(response.status).toBe(503);
    await expect(response.text()).resolves.not.toContain(secret);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("normalizes hostile handler option accessors without exposing their traps", async () => {
    const secret = "fixture-only-secret";
    const hostileError = new Proxy(
      {},
      {
        getPrototypeOf: () => {
          throw new Error(secret);
        },
      },
    );
    const options = new Proxy(
      {
        deploymentContext: secureContext,
        csrfValidated: () => true,
        rateLimitDecision: () => "allowed" as const,
        delegate: vi.fn(),
      },
      {
        get(target, property, receiver) {
          if (property === "deploymentContext") throw hostileError;
          return Reflect.get(target, property, receiver);
        },
      },
    ) as unknown as CreateOpaqueHandlerOptions;

    const handler = createOpaqueHandler(options);
    const response = await handler(request("{}"));

    expect(response.status).toBe(503);
    await expect(response.text()).resolves.not.toContain(secret);
  });

  it("uses one validated body-limit snapshot for the whole request", async () => {
    let bodyLimitReads = 0;
    const changingContext = Object.defineProperty({ ...secureContext }, "upstreamBodyLimitBytes", {
      configurable: false,
      enumerable: true,
      get: () => (bodyLimitReads++ < 4 ? MAX_HTTP_BODY_BYTES : 1),
    }) as NodeDeploymentContext;
    const delegate = vi.fn(() => ({ status: 200, body: new TextEncoder().encode('{"ok":true}') }));
    const handler = createOpaqueHandler({
      deploymentContext: changingContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate,
    });

    const response = await handler(request("{}"));

    expect(response.status).toBe(200);
    expect(delegate).toHaveBeenCalledOnce();
    expect(bodyLimitReads).toBe(4);
  });

  it("fails closed before reading a body when transport is not ready", async () => {
    const delegate = vi.fn();
    const handler = createOpaqueHandler({
      deploymentContext: { ...secureContext, transport: "plaintext" },
      csrfValidated: vi.fn(() => true),
      rateLimitDecision: () => "allowed",
      delegate,
    });

    const incoming = request('{"envelope":{}}');
    const response = await handler(incoming);

    expect(response.status).toBe(400);
    expect(incoming.bodyUsed).toBe(false);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("evaluates host CSRF validation before buffering the request body", async () => {
    const delegate = vi.fn();
    const csrfValidated = vi.fn(() => false);
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated,
      rateLimitDecision: () => "allowed",
      delegate,
    });
    const incoming = request('{"envelope":{}}');

    const response = await handler(incoming);

    expect(response.status).toBe(403);
    expect(csrfValidated).toHaveBeenCalledWith(incoming);
    expect(incoming.bodyUsed).toBe(false);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("rejects a content-length over the limit without buffering it", async () => {
    const delegate = vi.fn();
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate,
    });
    const incoming = request("{}", { "content-length": String(MAX_HTTP_BODY_BYTES + 1) });

    const response = await handler(incoming);

    expect(response.status).toBe(413);
    expect(incoming.bodyUsed).toBe(false);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("bounds chunked bodies before calling the cryptographic delegate", async () => {
    const delegate = vi.fn();
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate,
    });
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(MAX_HTTP_BODY_BYTES));
        controller.enqueue(new Uint8Array([1]));
      },
      cancel() {
        cancelled = true;
      },
    });
    const incoming = new Request("https://auth.example.test/v1/opaque/login/start", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: stream,
      duplex: "half",
    } as RequestInit & { duplex: "half" });

    const response = await handler(incoming);

    expect(response.status).toBe(413);
    expect(cancelled).toBe(true);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("does not copy non-byte stream chunks before rejecting the body", async () => {
    const delegate = vi.fn();
    const sourceChunk = new Uint16Array([0x1234, 0xabcd]);
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate,
    });
    const incoming = {
      url: "https://auth.example.test/v1/opaque/login/start",
      method: "POST",
      headers: new Headers({ "content-type": "application/json" }),
      body: new ReadableStream<unknown>({
        start(controller) {
          controller.enqueue(sourceChunk);
          controller.close();
        },
      }),
    } as unknown as Request;

    const response = await handler(incoming);

    expect(response.status).toBe(503);
    expect(sourceChunk.every((value) => value === 0)).toBe(true);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("keeps the oversized result deterministic when stream cancellation fails", async () => {
    const delegate = vi.fn();
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate,
    });
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(MAX_HTTP_BODY_BYTES));
        controller.enqueue(new Uint8Array([1]));
      },
      cancel() {
        return Promise.reject(new Error("transport cancellation failed"));
      },
    });
    const incoming = new Request("https://auth.example.test/v1/opaque/login/start", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: stream,
      duplex: "half",
    } as RequestInit & { duplex: "half" });

    const response = await handler(incoming);

    expect(response.status).toBe(413);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("normalizes hostile body-reader errors without exposing their traps", async () => {
    const secret = "fixture-only-secret";
    const hostileError = new Proxy(
      {},
      {
        getPrototypeOf: () => {
          throw new Error(secret);
        },
      },
    );
    const delegate = vi.fn();
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate,
    });
    const incoming = {
      url: "https://auth.example.test/v1/opaque/login/start",
      method: "POST",
      headers: new Headers({ "content-type": "application/json" }),
      body: {
        getReader: () => ({
          read: async () => {
            throw hostileError;
          },
          releaseLock: () => undefined,
        }),
      },
    } as unknown as Request;

    const response = await handler(incoming);

    expect(response.status).toBe(503);
    await expect(response.text()).resolves.not.toContain(secret);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("delegates only the bounded raw protocol body and applies fixed security headers", async () => {
    let received: NodeHttpRequest | undefined;
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate: (value) => {
        received = { ...value, body: value.body.slice() };
        return { status: 200, body: new TextEncoder().encode('{"authenticated":true}') };
      },
    });
    const incoming = request('{"protocolVersion":1}', { "content-type": JSON_CONTENT_TYPE });

    const response = await handler(incoming);

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(JSON_CONTENT_TYPE);
    for (const header of RESPONSE_SECURITY_HEADERS) {
      expect(response.headers.get(header.name)).toBe(header.value);
    }
    expect(received).toMatchObject({
      method: "POST",
      path: "/v1/opaque/login/start",
      contentType: JSON_CONTENT_TYPE,
      csrfValidated: true,
    });
    expect(new TextDecoder().decode(received?.body)).toBe('{"protocolVersion":1}');
  });

  it("zeroizes the bounded request buffer after the delegate returns", async () => {
    let receivedBody: Uint8Array | undefined;
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate: ({ body }) => {
        receivedBody = body;
        expect(new TextDecoder().decode(body)).toBe('{"protocolVersion":1}');
        return { status: 200, body: new TextEncoder().encode('{"ok":true}') };
      },
    });

    const response = await handler(request('{"protocolVersion":1}'));

    expect(response.status).toBe(200);
    expect(receivedBody).toBeDefined();
    expect(receivedBody?.every((byte) => byte === 0)).toBe(true);
  });

  it("zeroizes the delegate response buffer after copying it to the Fetch response", async () => {
    let responseBody: Uint8Array | undefined;
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate: () => {
        responseBody = new TextEncoder().encode('{"opaque":"sensitive-transport"}');
        return { status: 200, body: responseBody };
      },
    });

    const response = await handler(request('{"protocolVersion":1}'));

    expect(response.status).toBe(200);
    expect(responseBody).toBeDefined();
    expect(responseBody?.every((byte) => byte === 0)).toBe(true);
    expect(await response.text()).toBe('{"opaque":"sensitive-transport"}');
  });

  it("zeroizes malformed delegate response typed-array buffers before rejecting", async () => {
    const responseWords = new Uint16Array([0x1234, 0xabcd]);
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate: () => ({
        status: 200,
        body: responseWords as unknown as Uint8Array,
      }),
    });

    const response = await handler(request('{"protocolVersion":1}'));

    expect(response.status).toBe(503);
    expect(responseWords.every((word) => word === 0)).toBe(true);
  });

  it("clears stream chunks after copying the bounded request body", async () => {
    const chunk = new TextEncoder().encode('{"protocolVersion":1}');
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate: ({ body }) => {
        expect(new TextDecoder().decode(body)).toBe('{"protocolVersion":1}');
        return { status: 200, body: new TextEncoder().encode('{"ok":true}') };
      },
    });
    const incoming = new Request("https://auth.example.test/v1/opaque/login/start", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(chunk);
          controller.close();
        },
      }),
      duplex: "half",
    } as RequestInit & { duplex: "half" });

    const response = await handler(incoming);

    expect(response.status).toBe(200);
    expect(chunk.every((byte) => byte === 0)).toBe(true);
  });

  it("zeroizes the request buffer when the delegate fails", async () => {
    let receivedBody: Uint8Array | undefined;
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate: ({ body }) => {
        receivedBody = body;
        throw new Error("delegate failure");
      },
    });

    const response = await handler(request('{"protocolVersion":1}'));

    expect(response.status).toBe(503);
    expect(receivedBody?.every((byte) => byte === 0)).toBe(true);
  });

  it("does not trust forwarded headers and rejects delegate failures generically", async () => {
    const delegate = vi.fn(() => {
      throw new Error("secret-bearing internal failure");
    });
    const handler = createOpaqueHandler({
      deploymentContext: { ...secureContext, transport: "plaintext" },
      csrfValidated: () => true,
      rateLimitDecision: () => "allowed",
      delegate,
    });
    const incoming = request("{}", { "x-forwarded-proto": "https" });

    const response = await handler(incoming);

    expect(response.status).toBe(400);
    expect(delegate).not.toHaveBeenCalled();
  });
});
