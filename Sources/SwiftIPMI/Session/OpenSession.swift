import Foundation

public struct OpenSessionRequest: Sendable, Equatable {
    public var messageTag: UInt8
    public var requestedMaximumPrivilegeLevel: PrivilegeLevel
    public var consoleSessionID: UInt32

    public var authenticationAlgorithm: UInt8
    public var integrityAlgorithm: UInt8
    public var confidentialityAlgorithm: UInt8

    public init(
        messageTag: UInt8 = 0,
        requestedMaximumPrivilegeLevel: PrivilegeLevel,
        consoleSessionID: UInt32 = 0xA0A2A3A4,
        authenticationAlgorithm: UInt8 = 0x01,
        integrityAlgorithm: UInt8 = 0x01,
        confidentialityAlgorithm: UInt8 = 0x01
    ) {
        self.messageTag = messageTag
        self.requestedMaximumPrivilegeLevel = requestedMaximumPrivilegeLevel
        self.consoleSessionID = consoleSessionID
        self.authenticationAlgorithm = authenticationAlgorithm
        self.integrityAlgorithm = integrityAlgorithm
        self.confidentialityAlgorithm = confidentialityAlgorithm
    }

    public func encode() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(messageTag)
        bytes.append(UInt8(requestedMaximumPrivilegeLevel.rawValue))
        bytes.append(0x00)
        bytes.append(0x00)
        bytes += Endian.u32le(consoleSessionID)

        bytes += encodeAlgorithmPayload(type: 0x00, algorithm: authenticationAlgorithm)
        bytes += encodeAlgorithmPayload(type: 0x01, algorithm: integrityAlgorithm)
        bytes += encodeAlgorithmPayload(type: 0x02, algorithm: confidentialityAlgorithm)

        return bytes
    }

    private func encodeAlgorithmPayload(type: UInt8, algorithm: UInt8) -> [UInt8] {
        [
            type,
            0x00,
            0x00,
            0x08,
            algorithm,
            0x00,
            0x00,
            0x00
        ]
    }
}

public struct OpenSessionResponse: Sendable, Equatable {
    public var messageTag: UInt8
    public var statusCode: UInt8
    public var maximumPrivilegeLevel: UInt8
    public var consoleSessionID: UInt32
    public var managedSystemSessionID: UInt32
    public var authenticationAlgorithm: UInt8
    public var integrityAlgorithm: UInt8
    public var confidentialityAlgorithm: UInt8

    public init(
        messageTag: UInt8,
        statusCode: UInt8,
        maximumPrivilegeLevel: UInt8,
        consoleSessionID: UInt32,
        managedSystemSessionID: UInt32,
        authenticationAlgorithm: UInt8,
        integrityAlgorithm: UInt8,
        confidentialityAlgorithm: UInt8
    ) {
        self.messageTag = messageTag
        self.statusCode = statusCode
        self.maximumPrivilegeLevel = maximumPrivilegeLevel
        self.consoleSessionID = consoleSessionID
        self.managedSystemSessionID = managedSystemSessionID
        self.authenticationAlgorithm = authenticationAlgorithm
        self.integrityAlgorithm = integrityAlgorithm
        self.confidentialityAlgorithm = confidentialityAlgorithm
    }

    public static func decode(_ bytes: [UInt8]) throws -> OpenSessionResponse {
        guard bytes.count >= 36 else {
            throw OpenSessionError.invalidLength(expectedAtLeast: 36, actual: bytes.count)
        }

        let messageTag = bytes[0]
        let statusCode = bytes[1]
        let maximumPrivilegeLevel = bytes[2]
        let consoleSessionID = UInt32(bytes[4]) | (UInt32(bytes[5]) << 8) | (UInt32(bytes[6]) << 16) | (UInt32(bytes[7]) << 24)
        let managedSystemSessionID = UInt32(bytes[8]) | (UInt32(bytes[9]) << 8) | (UInt32(bytes[10]) << 16) | (UInt32(bytes[11]) << 24)

        let auth = bytes[16]
        let integ = bytes[24]
        let conf = bytes[32]

        return OpenSessionResponse(
            messageTag: messageTag,
            statusCode: statusCode,
            maximumPrivilegeLevel: maximumPrivilegeLevel,
            consoleSessionID: consoleSessionID,
            managedSystemSessionID: managedSystemSessionID,
            authenticationAlgorithm: auth,
            integrityAlgorithm: integ,
            confidentialityAlgorithm: conf
        )
    }
}

public enum OpenSessionError: Error, Sendable {
    case invalidLength(expectedAtLeast: Int, actual: Int)
    case nonZeroStatus(UInt8)
}
