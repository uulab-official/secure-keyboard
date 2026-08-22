import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const POLICY_PATH = fileURLToPath(new URL("../docs/PLATFORM-SUPPORT.json", import.meta.url));
export const PLATFORM_SUPPORT_POLICY = Object.freeze(JSON.parse(readFileSync(POLICY_PATH, "utf8")));

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const DOT_VERSION = /^\d+(?:\.\d+){1,3}$/;

function compareDotVersions(left, right) {
  const leftParts = left.split(".").map(Number);
  const rightParts = right.split(".").map(Number);
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = leftParts[index] ?? 0;
    const rightPart = rightParts[index] ?? 0;
    if (leftPart !== rightPart) return leftPart - rightPart;
  }
  return 0;
}

function isValidCalendarDate(value) {
  if (!ISO_DATE.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return date.toISOString().slice(0, 10) === value;
}

/**
 * Validates the platform support policy and returns human-readable findings.
 * The policy is checked independently so a malformed checked-in policy cannot
 * silently broaden a physical-device release gate.
 */
export function validatePlatformSupportPolicy(policy = PLATFORM_SUPPORT_POLICY) {
  const findings = [];
  if (policy?.schemaVersion !== 1) findings.push("schemaVersion must be 1");
  if (policy?.policyId !== "secure-keypad-platform-support-v1") {
    findings.push("policyId must identify the supported platform policy");
  }
  if (typeof policy?.effectiveDate !== "string" || !isValidCalendarDate(policy.effectiveDate)) {
    findings.push("effectiveDate must be a canonical calendar date");
  }
  const ios = policy?.platforms?.ios;
  if (ios?.minimumOsVersion !== "15.1") findings.push("ios minimumOsVersion must be 15.1");
  if (ios?.securityPatchFormat !== "dot-version") findings.push("ios securityPatchFormat must be dot-version");
  if (typeof ios?.minimumSecurityPatchLevel !== "string" || !DOT_VERSION.test(ios.minimumSecurityPatchLevel)) {
    findings.push("ios minimumSecurityPatchLevel must be a dotted version");
  }
  const android = policy?.platforms?.android;
  if (!Number.isSafeInteger(android?.minimumApiLevel) || android.minimumApiLevel < 24) {
    findings.push("android minimumApiLevel must be an integer of at least 24");
  }
  if (android?.securityPatchFormat !== "iso-date") {
    findings.push("android securityPatchFormat must be iso-date");
  }
  if (typeof android?.minimumSecurityPatchLevel !== "string" || !isValidCalendarDate(android.minimumSecurityPatchLevel)) {
    findings.push("android minimumSecurityPatchLevel must be a calendar date");
  }
  if (!DOT_VERSION.test(String(policy?.verifiedCiTargets?.iosSimulatorOsVersion))) {
    findings.push("verifiedCiTargets.iosSimulatorOsVersion must be a dotted version");
  }
  if (!Number.isSafeInteger(policy?.verifiedCiTargets?.androidApiLevel)) {
    findings.push("verifiedCiTargets.androidApiLevel must be an integer");
  }
  return findings;
}

/**
 * Validates a native device record against the checked-in support policy.
 * Security patch evidence is metadata only; the independent reviewer must
 * inspect the hashed `platform-security-patch` artifact before approval.
 */
export function validatePlatformSupportDevice(platform, device) {
  const findings = [];
  const policyFindings = validatePlatformSupportPolicy();
  if (policyFindings.length > 0) {
    return policyFindings.map((finding) => `platform policy: ${finding}`);
  }
  if (platform === "ios") {
    if (typeof device?.osVersion !== "string" || !DOT_VERSION.test(device.osVersion)) {
      findings.push("device.osVersion: must be a dotted iOS version");
    } else if (compareDotVersions(device.osVersion, PLATFORM_SUPPORT_POLICY.platforms.ios.minimumOsVersion) < 0) {
      findings.push("device.osVersion: is below the supported iOS minimum");
    }
    if (typeof device?.securityPatchLevel !== "string" || !DOT_VERSION.test(device.securityPatchLevel)) {
      findings.push("device.securityPatchLevel: must be a dotted iOS security version");
    } else if (
      compareDotVersions(
        device.securityPatchLevel,
        PLATFORM_SUPPORT_POLICY.platforms.ios.minimumSecurityPatchLevel,
      ) < 0
    ) {
      findings.push("device.securityPatchLevel: is below the iOS security patch floor");
    }
    return findings;
  }
  if (platform === "android") {
    if (!Number.isSafeInteger(device?.apiLevel)) {
      findings.push("device.apiLevel: must be an integer Android API level");
    } else if (device.apiLevel < PLATFORM_SUPPORT_POLICY.platforms.android.minimumApiLevel) {
      findings.push("device.apiLevel: is below the supported Android API minimum");
    }
    if (typeof device?.securityPatchLevel !== "string" || !isValidCalendarDate(device.securityPatchLevel)) {
      findings.push("device.securityPatchLevel: must be an ISO calendar date");
    } else if (device.securityPatchLevel < PLATFORM_SUPPORT_POLICY.platforms.android.minimumSecurityPatchLevel) {
      findings.push("device.securityPatchLevel: is below the Android security patch floor");
    }
    return findings;
  }
  return findings;
}
