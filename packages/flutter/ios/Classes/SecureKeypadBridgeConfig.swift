import Foundation
import UIKit

/// A framework-neutral public configuration decoded at the native boundary.
/// It contains layout and theme data only; no entered input is representable.
public struct SecureKeypadBridgeConfiguration {
    public let layout: SecureKeypadLayout
    public let theme: SecureKeypadTheme
    public let inputPolicy: String
    public let maxTokens: Int
    public let timeoutMs: UInt64

    public init(dictionary: NSDictionary) throws {
        guard Self.onlyKeys(dictionary, ["layout", "theme", "inputPolicy", "maxTokens", "timeoutMs"]) else {
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
    }

    private static func parseLayout(_ value: NSDictionary) throws -> SecureKeypadLayout {
        guard onlyKeys(value, ["schemaVersion", "id", "locale", "direction", "rows", "slots"]) else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        guard let schemaVersion = value["schemaVersion"] as? NSNumber, schemaVersion.intValue == 1 else {
            throw SecureKeypadBridgeConfigError.invalid
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
              onlyKeys(colors, ["background", "keyBackground", "keyForeground", "keyPressedBackground", "keyDisabledBackground", "error"]),
              onlyKeys(metrics, ["keyHeight", "keyGap", "keyRadius", "contentPadding"]),
              let keyHeight = number(metrics["keyHeight"]),
              let keyGap = number(metrics["keyGap"]),
              let keyRadius = number(metrics["keyRadius"]),
              let contentPadding = number(metrics["contentPadding"]),
              let background = color(colors["background"]),
              let keyColor = color(colors["keyBackground"]),
              let keyPressedColor = color(colors["keyPressedBackground"]),
              let keyTextColor = color(colors["keyForeground"]) else {
            throw SecureKeypadBridgeConfigError.invalid
        }
        guard keyHeight >= 1, keyHeight <= 256, keyGap >= 0, keyGap <= 256,
              keyRadius >= 0, keyRadius <= 256, contentPadding >= 0, contentPadding <= 256 else {
            throw SecureKeypadBridgeConfigError.invalid
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
        if let typography = value["typography"] as? NSDictionary,
           onlyKeys(typography, ["keyFontSize", "keyFontWeight"]),
           let fontSize = number(typography["keyFontSize"]),
           fontSize >= 1, fontSize <= 128 {
            theme.keyFontSize = CGFloat(fontSize)
        }
        return theme
    }

    private static func onlyKeys(_ value: NSDictionary, _ allowed: [String]) -> Bool {
        let allowedKeys = Set(allowed)
        return value.allKeys.allSatisfy { key in
            guard let key = key as? String else { return false }
            return allowedKeys.contains(key)
        }
    }

    private static func number(_ value: Any?) -> Double? {
        guard let number = value as? NSNumber else { return nil }
        let result = number.doubleValue
        return result.isFinite ? result : nil
    }

    private static func boundedInteger(_ value: Any?, default defaultValue: Int, range: ClosedRange<Int>) -> Int? {
        guard let value else { return defaultValue }
        guard !(value is Bool) else { return nil }
        guard let number = value as? NSNumber else { return nil }
        let result = number.doubleValue
        guard result.isFinite,
              result.rounded(.towardZero) == result,
              result >= Double(range.lowerBound),
              result <= Double(range.upperBound) else { return nil }
        return Int(result)
    }

    private static func color(_ value: Any?) -> UIColor? {
        guard let hex = value as? String else { return nil }
        let normalized = hex.dropFirst(hex.first == "#" ? 1 : 0)
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
