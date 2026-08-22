"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { withDangerousMod } = require("expo/config-plugins");

const PACKAGE_NAME = "@secure-keypad/react-native";
const IOS_FFI_ENV = "SECURE_KEYPAD_FFI_XCFRAMEWORK";
const ANDROID_FFI_ENV = "SECURE_KEYPAD_FFI_LIB_DIR";

function resolvePackageRoot(projectRoot) {
  const entryPath = require.resolve(PACKAGE_NAME, { paths: [projectRoot] });
  return path.resolve(path.dirname(entryPath), "..");
}

function requireDirectory(environmentName) {
  const configuredPath = process.env[environmentName];
  if (!configuredPath || !path.isAbsolute(configuredPath)) {
    throw new Error(`${environmentName} must be an absolute existing directory for an Expo development build`);
  }
  let realPath;
  try {
    realPath = fs.realpathSync(configuredPath);
  } catch (error) {
    throw new Error(`${environmentName} must point to an existing directory: ${error.message}`);
  }
  if (!fs.statSync(realPath).isDirectory()) {
    throw new Error(`${environmentName} must point to a directory`);
  }
  return realPath;
}

function requireBundledDirectory(projectRoot, relativePath) {
  const bundledPath = path.join(resolvePackageRoot(projectRoot), relativePath);
  let realPath;
  try {
    realPath = fs.realpathSync(bundledPath);
  } catch (error) {
    throw new Error(`bundled ${relativePath} must be present in the published package: ${error.message}`);
  }
  if (!fs.statSync(realPath).isDirectory()) {
    throw new Error(`bundled ${relativePath} must be a directory`);
  }
  return realPath;
}

function requireConfiguredOrBundledDirectory(projectRoot, environmentName, relativePath) {
  if (process.env[environmentName]) return requireDirectory(environmentName);
  return requireBundledDirectory(projectRoot, relativePath);
}

function stageIosFramework(projectRoot) {
  const sourcePath = requireConfiguredOrBundledDirectory(
    projectRoot,
    IOS_FFI_ENV,
    "secure_ffi.xcframework",
  );
  const targetPath = path.join(resolvePackageRoot(projectRoot), "secure_ffi.xcframework");
  if (fs.existsSync(targetPath) && fs.realpathSync(targetPath) === sourcePath) return;
  fs.cpSync(sourcePath, targetPath, { recursive: true, force: true, errorOnExist: false });
  if (!fs.existsSync(path.join(targetPath, "Info.plist"))) {
    throw new Error("staged secure_ffi.xcframework is missing Info.plist");
  }
}

/**
 * Makes the existing React Native native package consumable by Expo
 * Development Builds. Expo Go is intentionally unsupported because it cannot
 * load this package's custom native security boundary.
 */
function withSecureKeypad(config) {
  config = withDangerousMod(config, ["ios", async (config) => {
    stageIosFramework(config.modRequest.projectRoot);
    return config;
  }]);
  return withDangerousMod(config, ["android", async (config) => {
    requireConfiguredOrBundledDirectory(
      config.modRequest.projectRoot,
      ANDROID_FFI_ENV,
      "android/secure_ffi",
    );
    return config;
  }]);
}

module.exports = withSecureKeypad;
