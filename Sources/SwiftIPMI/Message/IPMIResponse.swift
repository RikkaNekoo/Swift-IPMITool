public struct IPMIResponse: Sendable {
    public var completionCode: UInt8
    public var data: [UInt8]

    public init(completionCode: UInt8, data: [UInt8] = []) {
        self.completionCode = completionCode
        self.data = data
    }
}
