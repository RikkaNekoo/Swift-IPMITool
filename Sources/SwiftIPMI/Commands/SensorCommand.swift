import Foundation

private func padRight(_ text: String, width: Int) -> String {
    if text.count >= width { return String(text.prefix(width)) }
    return text + String(repeating: " ", count: width - text.count)
}

private func formatThreshold(_ value: Double?) -> String {
    guard let value else { return "na" + String(repeating: " ", count: 7) }
    return String(format: "%-9.3f", value)
}

public enum SensorValueKind: Sendable, Equatable {
    case analog(Double, unit: String)
    case discrete(UInt8, state: UInt16)
    case unavailable
}

public struct SensorThresholds: Sendable, Equatable {
    public var lnr: Double?
    public var lcr: Double?
    public var lnc: Double?
    public var unc: Double?
    public var ucr: Double?
    public var unr: Double?

    public init(lnr: Double? = nil, lcr: Double? = nil, lnc: Double? = nil, unc: Double? = nil, ucr: Double? = nil, unr: Double? = nil) {
        self.lnr = lnr
        self.lcr = lcr
        self.lnc = lnc
        self.unc = unc
        self.ucr = ucr
        self.unr = unr
    }
}

public struct SensorRow: Sendable, Equatable {
    public var name: String
    public var valueKind: SensorValueKind
    public var status: String
    public var thresholds: SensorThresholds

    public init(name: String, valueKind: SensorValueKind, status: String, thresholds: SensorThresholds = .init()) {
        self.name = name
        self.valueKind = valueKind
        self.status = status
        self.thresholds = thresholds
    }
}

public enum SensorCommand {
    public static func render(rows: [SensorRow]) -> String {
        rows.map(renderRow).joined(separator: "\n")
    }

    private static func renderRow(_ row: SensorRow) -> String {
        let nameText = padRight(row.name, width: 16)

        let valueText: String
        let unitText: String
        let statusText: String

        switch row.valueKind {
        case let .analog(value, unit):
            valueText = padRight(String(format: "%.3f", value), width: 10)
            unitText = padRight(unit, width: 10)
            statusText = padRight(row.status, width: 6)
        case let .discrete(raw, state):
            valueText = padRight("0x\(String(raw, radix: 16))", width: 10)
            unitText = padRight("discrete", width: 10)
            statusText = row.status == "na" ? padRight("na", width: 6) : String(format: "0x%04X", state)
        case .unavailable:
            valueText = padRight("na", width: 10)
            unitText = padRight("", width: 10)
            statusText = padRight("na", width: 6)
        }

        let thresholds = [
            row.thresholds.lnr,
            row.thresholds.lcr,
            row.thresholds.lnc,
            row.thresholds.unc,
            row.thresholds.ucr,
            row.thresholds.unr
        ].map(formatThreshold)

        return "\(nameText) | \(valueText) | \(unitText) | \(statusText)| \(thresholds[0]) | \(thresholds[1]) | \(thresholds[2]) | \(thresholds[3]) | \(thresholds[4]) | \(thresholds[5]) "
    }
}
