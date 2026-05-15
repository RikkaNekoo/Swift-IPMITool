public struct IPMIRequest: Sendable {
    public var netFn: UInt8
    public var command: UInt8
    public var data: [UInt8]

    public init(netFn: UInt8, command: UInt8, data: [UInt8] = []) {
        self.netFn = netFn
        self.command = command
        self.data = data
    }
}
