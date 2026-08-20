import { describe, expect, it } from "vitest";
import { CONTRACT_VERSION } from "../src/index.js";

describe("contracts package", () => {
  it("exposes a versioned foundation contract", () => {
    expect(CONTRACT_VERSION).toBe(1);
  });
});
