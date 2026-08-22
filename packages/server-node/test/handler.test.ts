import { describe, expect, it, vi } from "vitest";
import {
  JSON_CONTENT_TYPE,
  MAX_HTTP_BODY_BYTES,
  RESPONSE_SECURITY_HEADERS,
  createOpaqueHandler,
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
  it("fails closed before reading a body when transport is not ready", async () => {
    const delegate = vi.fn();
    const handler = createOpaqueHandler({
      deploymentContext: { ...secureContext, transport: "plaintext" },
      csrfValidated: vi.fn(() => true),
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
    const handler = createOpaqueHandler({ deploymentContext: secureContext, csrfValidated, delegate });
    const incoming = request('{"envelope":{}}');

    const response = await handler(incoming);

    expect(response.status).toBe(403);
    expect(csrfValidated).toHaveBeenCalledWith(incoming);
    expect(incoming.bodyUsed).toBe(false);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("rejects a content-length over the limit without buffering it", async () => {
    const delegate = vi.fn();
    const handler = createOpaqueHandler({ deploymentContext: secureContext, csrfValidated: () => true, delegate });
    const incoming = request("{}", { "content-length": String(MAX_HTTP_BODY_BYTES + 1) });

    const response = await handler(incoming);

    expect(response.status).toBe(413);
    expect(incoming.bodyUsed).toBe(false);
    expect(delegate).not.toHaveBeenCalled();
  });

  it("bounds chunked bodies before calling the cryptographic delegate", async () => {
    const delegate = vi.fn();
    const handler = createOpaqueHandler({ deploymentContext: secureContext, csrfValidated: () => true, delegate });
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

  it("keeps the oversized result deterministic when stream cancellation fails", async () => {
    const delegate = vi.fn();
    const handler = createOpaqueHandler({ deploymentContext: secureContext, csrfValidated: () => true, delegate });
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

  it("delegates only the bounded raw protocol body and applies fixed security headers", async () => {
    let received: NodeHttpRequest | undefined;
    const handler = createOpaqueHandler({
      deploymentContext: secureContext,
      csrfValidated: () => true,
      delegate: (value) => {
        received = value;
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

  it("does not trust forwarded headers and rejects delegate failures generically", async () => {
    const delegate = vi.fn(() => {
      throw new Error("secret-bearing internal failure");
    });
    const handler = createOpaqueHandler({
      deploymentContext: { ...secureContext, transport: "plaintext" },
      csrfValidated: () => true,
      delegate,
    });
    const incoming = request("{}", { "x-forwarded-proto": "https" });

    const response = await handler(incoming);

    expect(response.status).toBe(400);
    expect(delegate).not.toHaveBeenCalled();
  });
});
