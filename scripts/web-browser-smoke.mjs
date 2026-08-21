import assert from "node:assert/strict";
import { createServer } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { chromium, firefox, webkit } from "playwright";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const WEB_ENTRY = path.join(ROOT, "packages/web/dist/index.js");
const BROWSERS = Object.freeze({ chromium, firefox, webkit });
const REQUESTED_BROWSER = process.argv[2] ?? "all";

if (REQUESTED_BROWSER !== "all" && !Object.hasOwn(BROWSERS, REQUESTED_BROWSER)) {
  console.error("usage: node scripts/web-browser-smoke.mjs [chromium|firefox|webkit|all]");
  process.exitCode = 64;
}

function contentType(pathname) {
  return pathname.endsWith(".js") ? "text/javascript; charset=utf-8" : "text/html; charset=utf-8";
}

function startServer() {
  const server = createServer((request, response) => {
    const pathname = new URL(request.url ?? "/", "http://localhost").pathname;
    if (pathname === "/") {
      response.writeHead(200, { "content-type": contentType(pathname), "cache-control": "no-store" });
      response.end("<!doctype html><meta charset=\"utf-8\"><title>Secure Keypad browser smoke</title>");
      return;
    }
    if (pathname !== "/packages/web/dist/index.js") {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, {
      "content-type": contentType(pathname),
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; script-src 'self'; connect-src 'self'",
    });
    response.end(readFileSync(WEB_ENTRY));
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("browser smoke server did not expose a TCP port"));
        return;
      }
      resolve({ server, url: `http://localhost:${address.port}/` });
    });
  });
}

async function closeServer(server) {
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
}

async function runBrowser(name, factory, url) {
  const browser = await factory.launch({ headless: true });
  const version = browser.version();
  try {
    const page = await browser.newPage({ serviceWorkers: "block" });
    await page.goto(url, { waitUntil: "load" });
    const result = await page.evaluate(async () => {
      const api = await import("/packages/web/dist/index.js?browser-smoke");
      const environment = api.getDefaultWebAuthnEnvironment();
      const support = api.detectWebAuthnSupport(environment);
      let fallbackRejected = false;
      try {
        api.assertWebAuthnMode("custom-keypad-fallback", environment, false);
      } catch (error) {
        fallbackRejected = error?.code === "fallback-not-acknowledged";
      }
      const encoded = api.encodeBase64Url(Uint8Array.from([0, 1, 2, 250]));
      const decoded = [...api.decodeBase64Url(encoded)];
      return {
        secureContext: environment.isSecureContext,
        supportAvailable: support.available,
        supportReason: support.reason ?? null,
        fallbackRejected,
        encoded,
        decoded,
        warningCode: api.getWebFallbackNotice().code,
      };
    });

    assert.equal(result.secureContext, true, `${name} must treat localhost as a secure context`);
    assert.deepEqual(result.decoded, [0, 1, 2, 250]);
    assert.equal(result.encoded, "AAEC-g");
    assert.equal(result.fallbackRejected, true);
    assert.equal(result.warningCode, "WEB_CUSTOM_KEYPAD_LOWER_ASSURANCE");
    assert.ok(result.supportAvailable || result.supportReason !== null);
    console.log(`${name}@${version}: secure-context pass; webauthn=${result.supportAvailable ? "available" : result.supportReason}`);
  } finally {
    await browser.close();
  }
}

async function main() {
  if (process.exitCode !== undefined) return;
  if (!existsSync(WEB_ENTRY)) {
    throw new Error("packages/web/dist/index.js is missing; run pnpm --dir packages/web build first");
  }
  const { server, url } = await startServer();
  try {
    const selected = REQUESTED_BROWSER === "all" ? Object.entries(BROWSERS) : [[REQUESTED_BROWSER, BROWSERS[REQUESTED_BROWSER]]];
    for (const [name, factory] of selected) await runBrowser(name, factory, url);
  } finally {
    await closeServer(server);
  }
}

main().catch((error) => {
  console.error(`web browser smoke failed: ${error.message}`);
  process.exitCode = 1;
});
