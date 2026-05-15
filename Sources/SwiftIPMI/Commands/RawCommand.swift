import Foundation

public struct RawResponse: Sendable, Equatable {
    public let completionCode: UInt8
    public let data: [UInt8]

    public init(completionCode: UInt8, data: [UInt8]) {
        self.completionCode = completionCode
        self.data = data
    }

    public func formattedOutput() -> String {
        guard completionCode == 0x00 else {
            return "Unable to send RAW command (ccode: 0x\(String(format: "%02x", completionCode)))"
        }
        guard !data.isEmpty else { return "" }
        return data.chunked(into: 16)
            .map { " " + $0.map { String(format: "%02x", $0) }.joined(separator: " ") }
            .joined(separator: "\n")
    }
}

private extension Array {
    func chunked(into size: Int) -> [[Element]] {
        stride(from: 0, to: count, by: size).map {
            Array(self[$0 ..< Swift.min($0 + size, count)])
        }
    }
}
