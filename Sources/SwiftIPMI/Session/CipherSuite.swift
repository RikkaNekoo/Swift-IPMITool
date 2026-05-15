public enum CipherSuite: UInt8, Sendable {
    case id0 = 0
    case id3 = 3
    case id17 = 17
}

public enum PrivilegeLevel: UInt8, Sendable {
    case callback = 1
    case user = 2
    case `operator` = 3
    case administrator = 4
    case oem = 5
}
