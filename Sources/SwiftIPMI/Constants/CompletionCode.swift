public enum CompletionCode: UInt8, Sendable {
    case success = 0x00
    case invalidCommand = 0xC1

    public var description: String {
        switch self {
        case .success: return "Command completed normally"
        case .invalidCommand: return "Invalid command"
        }
    }
}
