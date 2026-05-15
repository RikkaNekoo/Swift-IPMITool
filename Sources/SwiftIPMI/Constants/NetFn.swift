public enum NetFn: UInt8, Sendable {
    case app = 0x06
    case sensorEvent = 0x04
    case storage = 0x0A
}
