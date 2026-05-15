import CryptoKit
import Foundation

public enum RAKPAuthAlgorithm: UInt8, Sendable, Equatable {
    case hmacSHA1 = 0x01
    case hmacSHA256 = 0x03
}

public struct RAKPContext: Sendable, Equatable {
    public var consoleSessionID: UInt32
    public var managedSystemSessionID: UInt32
    public var consoleRandom: [UInt8]
    public var managedSystemRandom: [UInt8]
    public var managedSystemGUID: [UInt8]
    public var requestedPrivilegeLevel: PrivilegeLevel
    public var username: String

    public init(
        consoleSessionID: UInt32,
        managedSystemSessionID: UInt32,
        consoleRandom: [UInt8],
        managedSystemRandom: [UInt8],
        managedSystemGUID: [UInt8],
        requestedPrivilegeLevel: PrivilegeLevel,
        username: String
    ) {
        self.consoleSessionID = consoleSessionID
        self.managedSystemSessionID = managedSystemSessionID
        self.consoleRandom = consoleRandom
        self.managedSystemRandom = managedSystemRandom
        self.managedSystemGUID = managedSystemGUID
        self.requestedPrivilegeLevel = requestedPrivilegeLevel
        self.username = username
    }
}

public struct RAKPMessage1: Sendable, Equatable {
    public var messageTag: UInt8
    public var managedSystemSessionID: UInt32
    public var consoleRandom: [UInt8]
    public var requestedPrivilegeLevel: PrivilegeLevel
    public var username: String

    public func encode() -> [UInt8] {
        let user = Array(username.utf8)
        return [messageTag, 0x00, 0x00, 0x00]
            + Endian.u32le(managedSystemSessionID)
            + consoleRandom
            + [UInt8(requestedPrivilegeLevel.rawValue) | 0x10, 0x00, 0x00, UInt8(user.count)]
            + user
    }
}

public struct RAKPMessage2: Sendable, Equatable {
    public var messageTag: UInt8
    public var statusCode: UInt8
    public var consoleSessionID: UInt32
    public var managedSystemRandom: [UInt8]
    public var managedSystemGUID: [UInt8]
    public var keyExchangeAuthCode: [UInt8]

    public static func decode(_ bytes: [UInt8]) throws -> RAKPMessage2 {
        guard bytes.count >= 8 + 16 + 16 + 20 else {
            throw RAKPError.invalidLength(expectedAtLeast: 60, actual: bytes.count)
        }

        return RAKPMessage2(
            messageTag: bytes[0],
            statusCode: bytes[1],
            consoleSessionID: u32le(bytes, 4),
            managedSystemRandom: Array(bytes[8..<24]),
            managedSystemGUID: Array(bytes[24..<40]),
            keyExchangeAuthCode: Array(bytes[40..<bytes.count])
        )
    }
}

public struct RAKPMessage3: Sendable, Equatable {
    public var messageTag: UInt8
    public var statusCode: UInt8
    public var managedSystemSessionID: UInt32
    public var keyExchangeAuthCode: [UInt8]

    public func encode() -> [UInt8] {
        [messageTag, statusCode, 0x00, 0x00]
            + Endian.u32le(managedSystemSessionID)
            + keyExchangeAuthCode
    }
}

public struct RAKPMessage4: Sendable, Equatable {
    public var messageTag: UInt8
    public var statusCode: UInt8
    public var consoleSessionID: UInt32
    public var integrityCheckValue: [UInt8]

    public static func decode(_ bytes: [UInt8]) throws -> RAKPMessage4 {
        guard bytes.count >= 8 + 12 else {
            throw RAKPError.invalidLength(expectedAtLeast: 20, actual: bytes.count)
        }
        return RAKPMessage4(
            messageTag: bytes[0],
            statusCode: bytes[1],
            consoleSessionID: u32le(bytes, 4),
            integrityCheckValue: Array(bytes[8..<20])
        )
    }
}

public struct RAKPDerivedKeys: Sendable, Equatable {
    public var sik: [UInt8]
    public var k1: [UInt8]
    public var k2: [UInt8]
}

public enum RAKP {
    public static func passwordKey(_ password: String) -> [UInt8] {
        let input = Array(password.utf8)
        if input.count >= 20 { return Array(input.prefix(20)) }
        return input + Array(repeating: 0x00, count: 20 - input.count)
    }

    public static func computeRAKP2AuthCode(context: RAKPContext, password: String, algorithm: RAKPAuthAlgorithm = .hmacSHA256) -> [UInt8] {
        let user = Array(context.username.utf8)
        let payload = Endian.u32le(context.consoleSessionID)
            + Endian.u32le(context.managedSystemSessionID)
            + context.consoleRandom
            + context.managedSystemRandom
            + context.managedSystemGUID
            + [UInt8(context.requestedPrivilegeLevel.rawValue) | 0x10, UInt8(user.count)]
            + user
        return hmac(key: passwordKey(password), payload: payload, algorithm: algorithm)
    }

    public static func computeRAKP3AuthCode(context: RAKPContext, password: String, algorithm: RAKPAuthAlgorithm = .hmacSHA256) -> [UInt8] {
        let user = Array(context.username.utf8)
        // 按 IPMI v2.0 / ipmitool 行为：RAKP3 MAC 输入为 Rc | SIDm | ROLEm | ULENGTHm | USERNAME
        let payload = context.managedSystemRandom
            + Endian.u32le(context.consoleSessionID)
            + [UInt8(context.requestedPrivilegeLevel.rawValue) | 0x10, UInt8(user.count)]
            + user
        return hmac(key: passwordKey(password), payload: payload, algorithm: algorithm)
    }

    public static func deriveKeys(context: RAKPContext, password: String, algorithm: RAKPAuthAlgorithm = .hmacSHA256) -> RAKPDerivedKeys {
        let user = Array(context.username.utf8)
        let role = UInt8(context.requestedPrivilegeLevel.rawValue) | 0x10
        // SIK 输入需包含 ULENGTHm（与 ipmitool/规范一致）：Rm | Rc | ROLEm | ULENGTHm | USERNAME
        let sikSeed = context.consoleRandom + context.managedSystemRandom + [role, UInt8(user.count)] + user

        let sik = hmac(key: passwordKey(password), payload: sikSeed, algorithm: algorithm)
        let k1 = hmac(key: sik, payload: Array(repeating: 0x01, count: 20), algorithm: algorithm)
        let k2 = hmac(key: sik, payload: Array(repeating: 0x02, count: 20), algorithm: algorithm)

        return RAKPDerivedKeys(sik: sik, k1: k1, k2: k2)
    }

    public static func computeRAKP4IntegrityCheck(context: RAKPContext, sik: [UInt8], algorithm: RAKPAuthAlgorithm = .hmacSHA256) -> [UInt8] {
        let payload = context.consoleRandom
            + Endian.u32le(context.managedSystemSessionID)
            + context.managedSystemGUID
        return Array(hmac(key: sik, payload: payload, algorithm: algorithm).prefix(12))
    }

    private static func hmac(key: [UInt8], payload: [UInt8], algorithm: RAKPAuthAlgorithm) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: Data(key))
        switch algorithm {
        case .hmacSHA1:
            let mac = HMAC<Insecure.SHA1>.authenticationCode(for: Data(payload), using: symmetricKey)
            return Array(mac)
        case .hmacSHA256:
            let mac = HMAC<SHA256>.authenticationCode(for: Data(payload), using: symmetricKey)
            return Array(mac)
        }
    }
}

public enum RAKPError: Error, Sendable {
    case invalidLength(expectedAtLeast: Int, actual: Int)
    case nonZeroStatus(UInt8)
    case authCodeMismatch
    case integrityMismatch
}

private func u32le(_ bytes: [UInt8], _ start: Int) -> UInt32 {
    UInt32(bytes[start])
        | (UInt32(bytes[start + 1]) << 8)
        | (UInt32(bytes[start + 2]) << 16)
        | (UInt32(bytes[start + 3]) << 24)
}
