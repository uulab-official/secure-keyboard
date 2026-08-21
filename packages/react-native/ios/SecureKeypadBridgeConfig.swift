import Foundation
import UIKit

public struct SecureKeypadHeadlessKeyPress {
    public let token: Int64
    public let keyId: String
}

/// A framework-neutral public configuration decoded at the native boundary.
/// It contains layout and theme data only; no entered input is representable.
public struct SecureKeypadBridgeConfiguration {
    public let layout: SecureKeypadLayout
    public let theme: SecureKeypadTheme
    public let inputPolicy: String
    public let maxTokens: Int
    public let timeoutMs: UInt64
    public let mode: String
    public let acknowledgeLowerAssurance: Bool
    public let headlessKeyPress: SecureKeypadHeadlessKeyPress?

    public init(dictionary: NSDictionary) throws {
        guard Self.onlyKeys(dictionary, ["layout", "theme", "inputPolicy", "maxTokens", "timeoutMs", "mode", "acknowledgeLowerAssurance", "headlessKeyPress"]) else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        guard let layoutValue = dictionary["layout"] as? NSDictionary,
              let themeValue = dictionary["theme"] as? NSDictionary else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        layout = try Self.parseLayout(layoutValue)
        theme = try Self.parseTheme(themeValue)

        let policy = (dictionary["inputPolicy"] as? String) ?? "numeric"
        guard policy == "numeric" || policy == "ascii" || policy == "hangul" else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        inputPolicy = policy

        guard let parsedMaxTokens = Self.boundedInteger(dictionary["maxTokens"], default: 8, range: 1...4_096),
              let parsedTimeoutMs = Self.boundedInteger(dictionary["timeoutMs"], default: 60_000, range: 1...86_400_000) else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        maxTokens = parsedMaxTokens
        timeoutMs = UInt64(parsedTimeoutMs)
        let parsedMode = (dictionary["mode"] as? String) ?? "secure-native"
        guard parsedMode == "secure-native" || parsedMode == "headless-host" else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        let parsedAcknowledgement = Self.boolean(dictionary["acknowledgeLowerAssurance"]) ?? false
        guard (parsedMode == "secure-native" && !parsedAcknowledgement) ||
                (parsedMode == "headless-host" && parsedAcknowledgement) else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        mode = parsedMode
        acknowledgeLowerAssurance = parsedAcknowledgement
        headlessKeyPress = try Self.parseHeadlessKeyPress(dictionary["headlessKeyPress"], mode: parsedMode)
    }

    private static func parseHeadlessKeyPress(_ value: Any?, mode: String) throws -> SecureKeypadHeadlessKeyPress? {
        guard let value else { return nil }
        guard let dictionary = value as? NSDictionary,
              onlyKeys(dictionary, ["token", "keyId"]),
              let token = boundedInteger(dictionary["token"], minimum: 0, maximum: 9_007_199_254_740_991),
              let keyId = dictionary["keyId"] as? String,
              keyId.range(of: "^[a-z0-9][a-z0-9._-]{0,63}$", options: .regularExpression) != nil,
              mode == "headless-host" else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        return SecureKeypadHeadlessKeyPress(token: Int64(token), keyId: keyId)
    }

    private static func parseLayout(_ value: NSDictionary) throws -> SecureKeypadLayout {
        guard onlyKeys(value, ["schemaVersion", "id", "locale", "direction", "rows", "slots"]) else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        guard let schemaVersion = value["schemaVersion"] as? NSNumber, schemaVersion.intValue == 1 else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        if value.allKeys.contains(where: { ($0 as? String) == "id" }) {
            guard let id = value["id"] as? String,
                  id.range(of: "^[a-z0-9][a-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
                throw SecureKeypadBridgeConfigError.invalid
            }
        }
        if value.allKeys.contains(where: { ($0 as? String) == "locale" }) {
            guard let locale = value["locale"] as? String,
                  locale.range(of: "^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})?$", options: .regularExpression) != nil else {
                throw SecureKeypadBridgeConfigError.invalid
            }
        }
        if value.allKeys.contains(where: { ($0 as? String) == "direction" }) {
            guard value["direction"] as? String == "ltr" || value["direction"] as? String == "rtl" else {
                throw SecureKeypadBridgeConfigError.invalid
            }
        }
        if let slots = try Self.optionalMap(value["slots"], allowed: ["header", "display", "footer", "error"]) {
            guard slots.allValues.allSatisfy({ Self.boolean($0) != nil }) else {
                throw SecureKeypadBridgeConfigError.invalid
            }
        }
        guard let rows = value["rows"] as? NSArray, rows.count > 0, rows.count <= 16 else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        var parsedRows: [[SecureKeySpec]] = []
        var ids = Set<String>()
        for rowValue in rows {
            guard let row = rowValue as? NSArray, row.count > 0, row.count <= 32 else {
                throw SecureKeypadBridgeConfigError.invalid
            }
            var parsedRow: [SecureKeySpec] = []
            for keyValue in row {
                guard let key = keyValue as? NSDictionary,
                      onlyKeys(key, ["id", "label", "icon", "role", "accessibilityLabel", "testId"]),
                      let id = key["id"] as? String,
                      let roleValue = key["role"] as? String,
                      let role = SecureKeyRole(rawValue: roleValue),
                      id.utf8.count <= 64,
                      id.utf8.count > 0,
                      id.unicodeScalars.allSatisfy({ $0.value < 128 }),
                      id.range(of: "^[a-z0-9][a-z0-9._-]{0,63}$", options: .regularExpression) != nil,
                      ids.insert(id).inserted else {
                    throw SecureKeypadBridgeConfigError.invalid
                }
                if key.allKeys.contains(where: { ($0 as? String) == "label" }) {
                    guard key["label"] is String else { throw SecureKeypadBridgeConfigError.invalid }
                }
                for field in ["icon", "testId"] {
                    if key.allKeys.contains(where: { ($0 as? String) == field }) {
                        guard let publicId = key[field] as? String,
                              publicId.range(of: "^[a-z0-9][a-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
                            throw SecureKeypadBridgeConfigError.invalid
                        }
                    }
                }
                if key.allKeys.contains(where: { ($0 as? String) == "accessibilityLabel" }) {
                    guard key["accessibilityLabel"] is String else { throw SecureKeypadBridgeConfigError.invalid }
                }
                let label = (key["label"] as? String) ?? (key["icon"] as? String) ?? id
                guard label.utf8.count <= 16 else {
                    throw SecureKeypadBridgeConfigError.invalid
                }
                let accessibilityLabel = (key["accessibilityLabel"] as? String) ?? label
                guard accessibilityLabel.utf8.count <= 80 else {
                    throw SecureKeypadBridgeConfigError.invalid
                }
                parsedRow.append(SecureKeySpec(
                    id: id,
                    label: label,
                    role: role,
                    accessibilityLabel: accessibilityLabel
                ))
            }
            parsedRows.append(parsedRow)
        }
        return SecureKeypadLayout(rows: parsedRows)
    }

    private static func parseTheme(_ value: NSDictionary) throws -> SecureKeypadTheme {
        guard onlyKeys(value, ["schemaVersion", "colors", "metrics", "typography", "animation", "feedback"]) else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        guard let schemaVersion = value["schemaVersion"] as? NSNumber,
              schemaVersion.intValue == 1,
              let colors = value["colors"] as? NSDictionary,
              let metrics = value["metrics"] as? NSDictionary,
              exactKeys(colors, ["background", "keyBackground", "keyForeground", "keyPressedBackground", "keyDisabledBackground", "error"]),
              exactKeys(metrics, ["keyHeight", "keyGap", "keyRadius", "contentPadding"]),
              let typography = try Self.optionalMap(value["typography"], allowed: ["keyFontSize", "keyFontWeight"]),
              let keyHeight = number(metrics["keyHeight"]),
              let keyGap = number(metrics["keyGap"]),
              let keyRadius = number(metrics["keyRadius"]),
              let contentPadding = number(metrics["contentPadding"]),
              let background = color(colors["background"]),
              let keyColor = color(colors["keyBackground"]),
              let keyPressedColor = color(colors["keyPressedBackground"]),
              let keyTextColor = color(colors["keyForeground"]),
              color(colors["keyDisabledBackground"]) != nil,
              color(colors["error"]) != nil else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        guard keyHeight >= 32, keyHeight <= 160, keyGap >= 0, keyGap <= 48,
              keyRadius >= 0, keyRadius <= 80, contentPadding >= 0, contentPadding <= 80,
              let keyFontSize = number(typography["keyFontSize"]), keyFontSize >= 10, keyFontSize <= 72,
              validFontWeight(typography["keyFontWeight"]) else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        if let animation = try Self.optionalMap(value["animation"], allowed: ["pressDurationMs", "maskRevealDurationMs"]) {
            if animation.allKeys.contains(where: { ($0 as? String) == "pressDurationMs" }) {
                guard let duration = boundedInteger(animation["pressDurationMs"], minimum: 0, maximum: 500) else {
                    throw SecureKeypadBridgeConfigError.invalid
                }
                _ = duration
            }
            if animation.allKeys.contains(where: { ($0 as? String) == "maskRevealDurationMs" }) {
                guard let duration = boundedInteger(animation["maskRevealDurationMs"], minimum: 0, maximum: 2_000) else {
                    throw SecureKeypadBridgeConfigError.invalid
                }
                _ = duration
            }
        }
        if let feedback = try Self.optionalMap(value["feedback"], allowed: ["haptic", "sound"]) {
            if feedback.allKeys.contains(where: { ($0 as? String) == "haptic" }) {
                guard let haptic = feedback["haptic"] as? String,
                      ["none", "light", "medium", "heavy"].contains(haptic) else {
                    throw SecureKeypadBridgeConfigError.invalid
                }
            }
            if feedback.allKeys.contains(where: { ($0 as? String) == "sound" }) {
                guard let sound = feedback["sound"] as? String, ["none", "click"].contains(sound) else {
                    throw SecureKeypadBridgeConfigError.invalid
                }
            }
        }
        var theme = SecureKeypadTheme()
        theme.backgroundColor = background
        theme.keyColor = keyColor
        theme.keyPressedColor = keyPressedColor
        theme.keyTextColor = keyTextColor
        theme.keyHeight = CGFloat(keyHeight)
        theme.keyGap = CGFloat(keyGap)
        theme.keyRadius = CGFloat(keyRadius)
        theme.contentPadding = CGFloat(contentPadding)
        theme.keyFontSize = CGFloat(keyFontSize)
        return theme
    }

    private static func onlyKeys(_ value: NSDictionary, _ allowed: [String]) -> Bool {
        let allowedKeys = Set(allowed)
        return value.allKeys.allSatisfy { key in
            guard let key = key as? String else { return false }
            return allowedKeys.contains(key)
        }
    }

    private static func exactKeys(_ value: NSDictionary, _ required: [String]) -> Bool {
        onlyKeys(value, required) && value.count == Set(required).count
    }

    private static func number(_ value: Any?) -> Double? {
        guard let number = value as? NSNumber else { return nil }
        guard !isBooleanNumber(number) else { return nil }
        let result = number.doubleValue
        return result.isFinite ? result : nil
    }

    private static func boundedInteger(_ value: Any?, minimum: Double, maximum: Double) -> Int? {
        guard let number = value as? NSNumber else { return nil }
        guard !isBooleanNumber(number) else { return nil }
        let result = number.doubleValue
        guard result.isFinite, result.rounded(.towardZero) == result, result >= minimum, result <= maximum else {
            return nil
        }
        return Int(result)
    }

    private static func validFontWeight(_ value: Any?) -> Bool {
        if let string = value as? String {
            return ["400", "500", "600", "700"].contains(string)
        }
        guard let weight = boundedInteger(value, minimum: 400, maximum: 700) else { return false }
        return [400, 500, 600, 700].contains(weight)
    }

    private static func optionalMap(_ value: Any?, allowed: [String]) throws -> NSDictionary? {
        guard let value else { return nil }
        guard let dictionary = value as? NSDictionary, onlyKeys(dictionary, allowed) else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        return dictionary
    }

    private static func boundedInteger(_ value: Any?, default defaultValue: Int, range: ClosedRange<Int>) -> Int? {
        guard let value else { return defaultValue }
        guard let number = value as? NSNumber else { return nil }
        guard !isBooleanNumber(number) else { return nil }
        let result = number.doubleValue
        guard result.isFinite,
              result.rounded(.towardZero) == result,
              result >= Double(range.lowerBound),
              result <= Double(range.upperBound) else { return nil }
        return Int(result)
    }

    private static func isBooleanNumber(_ value: NSNumber) -> Bool {
        CFGetTypeID(value) == CFBooleanGetTypeID()
    }

    private static func boolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, isBooleanNumber(number) else { return nil }
        return number.boolValue
    }

    private static func color(_ value: Any?) -> UIColor? {
        guard let hex = value as? String else { return nil }
        guard hex.hasPrefix("#") else { return nil }
        let normalized = hex.dropFirst()
        guard normalized.count == 6 || normalized.count == 8,
              let raw = UInt64(normalized, radix: 16) else { return nil }
        let alpha: CGFloat
        let red: CGFloat
        let green: CGFloat
        let blue: CGFloat
        if normalized.count == 6 {
            alpha = 1
            red = CGFloat((raw >> 16) & 0xff) / 255
            green = CGFloat((raw >> 8) & 0xff) / 255
            blue = CGFloat(raw & 0xff) / 255
        } else {
            red = CGFloat((raw >> 24) & 0xff) / 255
            green = CGFloat((raw >> 16) & 0xff) / 255
            blue = CGFloat((raw >> 8) & 0xff) / 255
            alpha = CGFloat(raw & 0xff) / 255
        }
        return UIColor(red: red, green: green, blue: blue, alpha: alpha)
    }
}

public enum SecureKeypadBridgeConfigError: Error {
    case invalid
}
