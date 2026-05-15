import Darwin

public struct VerboseLogger: Sendable {
    public let isEnabled: Bool

    public init(isEnabled: Bool = false) {
        self.isEnabled = isEnabled
    }

    public func log(_ message: @autoclosure () -> String) {
        guard isEnabled else { return }
        fputs(message() + "\n", stderr)
        fflush(stderr)
    }

    public func logHexDump(prefix: String, bytes: [UInt8]) {
        guard isEnabled else { return }
        let hex = bytes.map { String(format: "%02x", $0) }.joined(separator: " ")
        fputs("\(prefix): \(hex)\n", stderr)
        fflush(stderr)
    }
}
