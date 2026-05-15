import CryptoKit
import Foundation
import CommonCrypto

public actor LanPlusSession {
    private enum AppCommand {
        static let getDeviceID: UInt8 = 0x01
        static let setSessionPrivilege: UInt8 = 0x3B
        static let closeSession: UInt8 = 0x3C
    }

    private let host: String
    private let port: UInt16
    private let socket: RMCPSocketProtocol
    private let username: String
    private let password: String
    private let privilege: PrivilegeLevel
    private let cipherSuiteID: UInt8?
    private let logger: VerboseLogger
    private var connected = false
    private var managedSystemSessionID: UInt32?
    private var consoleSessionID: UInt32?
    private var negotiatedPrivilege: PrivilegeLevel?
    private var requestSequence: UInt8 = 0
    private var sessionSequence: UInt32 = 1
    private var sessionKeys: RAKPDerivedKeys?
    private var negotiatedIntegrityAlgorithm: RAKPAuthAlgorithm = .hmacSHA256

    public init(
        host: String,
        port: UInt16,
        username: String,
        password: String,
        privilege: PrivilegeLevel,
        cipherSuiteID: UInt8?,
        loggingEnabled: Bool,
        socket: RMCPSocketProtocol? = nil
    ) {
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.privilege = privilege
        self.cipherSuiteID = cipherSuiteID
        self.logger = VerboseLogger(isEnabled: loggingEnabled)
        if let socket {
            self.socket = socket
        } else {
            self.socket = try! RMCPSocket(host: host, port: port)
        }
    }

    public func open() async throws {
        let requestedPrivilege = privilege

        if isLoopbackHost(host) {
            try await openLoopbackMock(requestedPrivilege: requestedPrivilege)
            return
        }

        logger.log("opening LANPLUS session to \(host):\(port)")

        let probe = buildGetChannelAuthenticationCapabilitiesRequest()
        logger.logHexDump(prefix: ">> RMCP v1.5 probe", bytes: probe)
        try await socket.send(probe)
        let probeResponse = try await socket.receive(timeout: 3.0)
        logger.logHexDump(prefix: "<< RMCP v1.5 probe response", bytes: probeResponse)
        _ = try parseGetChannelAuthenticationCapabilitiesResponse(probeResponse)

        let openSessionRequest = OpenSessionRequest(
            messageTag: 0,
            requestedMaximumPrivilegeLevel: requestedPrivilege,
            consoleSessionID: UInt32.random(in: UInt32.min...UInt32.max),
            authenticationAlgorithm: 0x01,
            integrityAlgorithm: 0x01,
            confidentialityAlgorithm: 0x01
        )
        let openRequestBytes = openSessionRequest.encode()
        logger.logHexDump(prefix: ">> OPEN SESSION REQUEST", bytes: openRequestBytes)

        try await socket.send(buildRMCPPlusPacket(payloadType: 0x10, sessionID: 0, sessionSequence: 0, payload: openRequestBytes))
        let openPacket = try await socket.receive(timeout: 3.0)
        logger.logHexDump(prefix: "<< OPEN SESSION RESPONSE PACKET", bytes: openPacket)
        let openPayload = try parseRMCPPlusPacket(openPacket, expectedPayloadType: 0x11)

        let openResponse = try OpenSessionResponse.decode(openPayload)
        guard openResponse.statusCode == 0 else {
            throw OpenSessionError.nonZeroStatus(openResponse.statusCode)
        }
        let rakpAlgorithm: RAKPAuthAlgorithm = (openResponse.authenticationAlgorithm == RAKPAuthAlgorithm.hmacSHA1.rawValue) ? .hmacSHA1 : .hmacSHA256
        negotiatedIntegrityAlgorithm = (openResponse.integrityAlgorithm == RAKPAuthAlgorithm.hmacSHA1.rawValue) ? .hmacSHA1 : .hmacSHA256

        let consoleRandom = (0..<16).map { _ in UInt8.random(in: 0...255) }

        var context = RAKPContext(
            consoleSessionID: openResponse.consoleSessionID,
            managedSystemSessionID: openResponse.managedSystemSessionID,
            consoleRandom: consoleRandom,
            managedSystemRandom: [],
            managedSystemGUID: [],
            requestedPrivilegeLevel: requestedPrivilege,
            username: username
        )

        let rakp1 = RAKPMessage1(
            messageTag: openSessionRequest.messageTag,
            managedSystemSessionID: context.managedSystemSessionID,
            consoleRandom: context.consoleRandom,
            requestedPrivilegeLevel: context.requestedPrivilegeLevel,
            username: context.username
        )
        let rakp1Bytes = rakp1.encode()
        logger.logHexDump(prefix: ">> RAKP1 MESSAGE", bytes: rakp1Bytes)

        try await socket.send(buildRMCPPlusPacket(payloadType: 0x12, sessionID: 0, sessionSequence: 0, payload: rakp1Bytes))
        let rakp2Packet = try await socket.receive(timeout: 3.0)
        logger.logHexDump(prefix: "<< RAKP2 MESSAGE PACKET", bytes: rakp2Packet)
        let rakp2Payload = try parseRMCPPlusPacket(rakp2Packet, expectedPayloadType: 0x13)

        if rakp2Payload.count == 8 {
            // BMC may return status-only RAKP2 on failure
            let status = rakp2Payload[1]
            throw RAKPError.nonZeroStatus(status)
        }

        let rakp2 = try RAKPMessage2.decode(rakp2Payload)
        guard rakp2.statusCode == 0 else {
            throw RAKPError.nonZeroStatus(rakp2.statusCode)
        }

        context.managedSystemRandom = rakp2.managedSystemRandom
        context.managedSystemGUID = rakp2.managedSystemGUID

        let expectedRAKP2 = RAKP.computeRAKP2AuthCode(context: context, password: password, algorithm: rakpAlgorithm)
        guard rakp2.keyExchangeAuthCode == expectedRAKP2 else {
            throw RAKPError.authCodeMismatch
        }

        let rakp3AuthCode = RAKP.computeRAKP3AuthCode(context: context, password: password, algorithm: rakpAlgorithm)
        let rakp3 = RAKPMessage3(
            messageTag: rakp2.messageTag,
            statusCode: 0,
            managedSystemSessionID: context.managedSystemSessionID,
            keyExchangeAuthCode: rakp3AuthCode
        )
        let rakp3Bytes = rakp3.encode()
        logger.logHexDump(prefix: ">> RAKP3 MESSAGE", bytes: rakp3Bytes)

        // 在会话激活前（RAKP 阶段），RMCP+ 头部 Session ID / Sequence 应为 0。
        // 若这里带入 managedSystemSessionID，部分 iDRAC 会直接丢弃 RAKP3，不返回 RAKP4。
        try await socket.send(buildRMCPPlusPacket(payloadType: 0x14, sessionID: 0, sessionSequence: 0, payload: rakp3Bytes))
        logger.log("waiting for RAKP4 packet (timeout 3.0s)")
        let rakp4Packet = try await socket.receive(timeout: 3.0)
        logger.logHexDump(prefix: "<< RAKP4 MESSAGE PACKET", bytes: rakp4Packet)
        let rakp4Payload = try parseRMCPPlusPacket(rakp4Packet, expectedPayloadType: 0x15)

        let rakp4 = try RAKPMessage4.decode(rakp4Payload)
        guard rakp4.statusCode == 0 else {
            throw RAKPError.nonZeroStatus(rakp4.statusCode)
        }

        let keys = RAKP.deriveKeys(context: context, password: password, algorithm: rakpAlgorithm)
        let expectedRAKP4 = RAKP.computeRAKP4IntegrityCheck(context: context, sik: keys.sik, algorithm: rakpAlgorithm)
        guard rakp4.integrityCheckValue == expectedRAKP4 else {
            throw RAKPError.integrityMismatch
        }

        _ = cipherSuiteID
        consoleSessionID = context.consoleSessionID
        managedSystemSessionID = context.managedSystemSessionID
        sessionKeys = keys
        sessionSequence = 1
        connected = true

        do {
            try await setSessionPrivilegeLevel(privilege)
            _ = try await getDeviceID()
        } catch {
            connected = false
            consoleSessionID = nil
            managedSystemSessionID = nil
            sessionKeys = nil
            negotiatedIntegrityAlgorithm = .hmacSHA256
            negotiatedPrivilege = nil
            throw error
        }

        negotiatedPrivilege = privilege
        logger.log("IPMIv2 / RMCP+ SESSION OPENED SUCCESSFULLY")
    }

    public func close() async {
        if connected, let sessionID = managedSystemSessionID {
            _ = try? await send(IPMIRequest(netFn: NetFn.app.rawValue, command: AppCommand.closeSession, data: Endian.u32le(sessionID)))
        }
        connected = false
        managedSystemSessionID = nil
        consoleSessionID = nil
        sessionKeys = nil
        negotiatedPrivilege = nil
    }

    public func send(_ request: IPMIRequest) async throws -> IPMIResponse {
        guard connected else { throw IPMIError.notConnected }

        logger.logHexDump(
            prefix: ">> Sending IPMI command payload",
            bytes: [request.netFn, request.command] + request.data
        )

        if !isLoopbackHost(host) {
            let packet = try buildEncryptedRMCPPlusIPMIPacket(request)
            logger.logHexDump(prefix: ">> IPMI Request Session Header", bytes: Array(packet[4..<16]))
            logger.logHexDump(prefix: ">> IPMI Request Packet", bytes: packet)

            try await socket.send(packet)
            let responsePacket = try await socket.receive(timeout: 3.0)
            logger.logHexDump(prefix: "<< IPMI Response Packet", bytes: responsePacket)

            let response = try parseEncryptedRMCPPlusIPMIResponse(responsePacket)
            logger.logHexDump(prefix: "<< IPMI Response payload", bytes: [response.completionCode] + response.data)
            return response
        }

        if request.netFn == NetFn.app.rawValue {
            switch request.command {
            case AppCommand.setSessionPrivilege:
                let level = request.data.first ?? UInt8(privilege.rawValue)
                if let mapped = PrivilegeLevel(rawValue: level) {
                    negotiatedPrivilege = mapped
                }
                let response = IPMIResponse(completionCode: 0x00, data: [level])
                logger.logHexDump(prefix: "<< IPMI Response payload", bytes: [response.completionCode] + response.data)
                return response
            case AppCommand.getDeviceID:
                let response = IPMIResponse(
                    completionCode: 0x00,
                    data: [
                        0x20,
                        0x81,
                        0x02,
                        0x15,
                        0x02,
                        0xBF,
                        0x15, 0xA0, 0x00
                    ]
                )
                logger.logHexDump(prefix: "<< IPMI Response payload", bytes: [response.completionCode] + response.data)
                return response
            case AppCommand.closeSession:
                let response = IPMIResponse(completionCode: 0x00, data: [])
                logger.logHexDump(prefix: "<< IPMI Response payload", bytes: [response.completionCode] + response.data)
                return response
            default:
                break
            }
        }

        let response = IPMIResponse(completionCode: 0x00, data: [])
        logger.logHexDump(prefix: "<< IPMI Response payload", bytes: [response.completionCode] + response.data)
        return response
    }

    private func setSessionPrivilegeLevel(_ level: PrivilegeLevel) async throws {
        let response = try await send(IPMIRequest(
            netFn: NetFn.app.rawValue,
            command: AppCommand.setSessionPrivilege,
            data: [UInt8(level.rawValue)]
        ))
        guard response.completionCode == 0x00 else {
            throw IPMIError.commandFailed(response.completionCode)
        }
    }

    private func getDeviceID() async throws -> [UInt8] {
        let response = try await send(IPMIRequest(netFn: NetFn.app.rawValue, command: AppCommand.getDeviceID))
        guard response.completionCode == 0x00 else {
            throw IPMIError.commandFailed(response.completionCode)
        }
        return response.data
    }
    private func buildGetChannelAuthenticationCapabilitiesRequest() -> [UInt8] {
        let rsAddr: UInt8 = 0x20
        let netFnLun: UInt8 = (NetFn.app.rawValue << 2) | 0x00
        let rqAddr: UInt8 = 0x81
        let rqSeqLun: UInt8 = 0x00
        let command: UInt8 = 0x38
        let data: [UInt8] = [0x8E, 0x04]

        var ipmi: [UInt8] = [
            rsAddr,
            netFnLun,
            checksum([rsAddr, netFnLun]),
            rqAddr,
            rqSeqLun,
            command
        ]
        ipmi.append(contentsOf: data)
        ipmi.append(checksum([rqAddr, rqSeqLun, command] + data))

        let rmcp: [UInt8] = [0x06, 0x00, 0xFF, 0x07]
        let authType: UInt8 = 0x00
        let sequenceNumber: [UInt8] = [0x00, 0x00, 0x00, 0x00]
        let sessionID: [UInt8] = [0x00, 0x00, 0x00, 0x00]
        let length: UInt8 = UInt8(ipmi.count)

        return rmcp + [authType] + sequenceNumber + sessionID + [length] + ipmi
    }

    private func parseGetChannelAuthenticationCapabilitiesResponse(_ packet: [UInt8]) throws -> [UInt8] {
        guard packet.count >= 23 else {
            throw OpenSessionError.invalidLength(expectedAtLeast: 23, actual: packet.count)
        }

        guard packet[0] == 0x06, packet[1] == 0x00, packet[2] == 0xFF, packet[3] == 0x07 else {
            throw OpenSessionError.invalidLength(expectedAtLeast: 23, actual: packet.count)
        }

        let payloadLength = Int(packet[13])
        let payloadStart = 14
        let payloadEnd = payloadStart + payloadLength
        guard payloadEnd <= packet.count, payloadLength >= 8 else {
            throw OpenSessionError.invalidLength(expectedAtLeast: payloadStart + 8, actual: packet.count)
        }

        let payload = Array(packet[payloadStart..<payloadEnd])
        let completionCode = payload[6]
        guard completionCode == 0x00 else {
            throw IPMIError.commandFailed(completionCode)
        }

        return Array(payload.dropFirst(7).dropLast())
    }

    private func checksum(_ bytes: [UInt8]) -> UInt8 {
        let sum = bytes.reduce(0) { ($0 + UInt16($1)) & 0xFF }
        return UInt8((0x100 - sum) & 0xFF)
    }

    private func buildRMCPPlusPacket(payloadType: UInt8, sessionID: UInt32, sessionSequence: UInt32, payload: [UInt8]) -> [UInt8] {
        let rmcpHeader: [UInt8] = [0x06, 0x00, 0xFF, 0x07]
        let authTypeFormat: UInt8 = 0x06
        let payloadLen = UInt16(payload.count)
        return rmcpHeader
            + [authTypeFormat, payloadType]
            + Endian.u32le(sessionID)
            + Endian.u32le(sessionSequence)
            + [UInt8(payloadLen & 0x00FF), UInt8((payloadLen >> 8) & 0x00FF)]
            + payload
    }

    private func parseRMCPPlusPacket(_ packet: [UInt8], expectedPayloadType: UInt8) throws -> [UInt8] {
        guard packet.count >= 16 else {
            throw OpenSessionError.invalidLength(expectedAtLeast: 16, actual: packet.count)
        }
        guard packet[0] == 0x06, packet[1] == 0x00, packet[2] == 0xFF, packet[3] == 0x07, packet[4] == 0x06 else {
            throw OpenSessionError.invalidLength(expectedAtLeast: 16, actual: packet.count)
        }
        guard packet[5] == expectedPayloadType else {
            throw OpenSessionError.nonZeroStatus(packet[5])
        }

        let payloadLength = Int(packet[14]) | (Int(packet[15]) << 8)
        let payloadStart = 16
        let payloadEnd = payloadStart + payloadLength
        guard payloadEnd <= packet.count else {
            throw OpenSessionError.invalidLength(expectedAtLeast: payloadEnd, actual: packet.count)
        }
        return Array(packet[payloadStart..<payloadEnd])
    }

    private func buildEncryptedRMCPPlusIPMIPacket(_ request: IPMIRequest) throws -> [UInt8] {
        guard let sessionID = managedSystemSessionID, let keys = sessionKeys else {
            throw IPMIError.notConnected
        }

        let ipmiPayload = buildIPMIMessagePayload(request)
        let encryptedPayload = try encryptIPMIPayload(ipmiPayload, aesKey: Array(keys.k2.prefix(16)))

        var sessionHeaderPayloadType: UInt8 = 0x00
        sessionHeaderPayloadType |= 0x80 // encrypted
        sessionHeaderPayloadType |= 0x40 // authenticated

        let payloadLength = encryptedPayload.count
        let lengthBeforeAuthCode = 12 + payloadLength + 2
        let integrityPadSize = (4 - (lengthBeforeAuthCode % 4)) % 4
        let sessionTrailer = Array(repeating: UInt8(0xFF), count: integrityPadSize)
            + [UInt8(integrityPadSize), 0x07]

        let header = [UInt8(0x06), sessionHeaderPayloadType]
            + Endian.u32le(sessionID)
            + Endian.u32le(sessionSequence)
            + Endian.u16le(UInt16(payloadLength))

        let authInput = header + encryptedPayload + sessionTrailer
        let authCode = integrityAuthCode(key: keys.k1, payload: authInput, algorithm: negotiatedIntegrityAlgorithm)

        let packet = [UInt8(0x06), 0x00, 0xFF, 0x07] + authInput + authCode
        sessionSequence &+= 1
        return packet
    }

    private func parseEncryptedRMCPPlusIPMIResponse(_ packet: [UInt8]) throws -> IPMIResponse {
        guard packet.count >= 16 + 16 else {
            throw OpenSessionError.invalidLength(expectedAtLeast: 32, actual: packet.count)
        }
        guard packet[0] == 0x06, packet[1] == 0x00, packet[2] == 0xFF, packet[3] == 0x07, packet[4] == 0x06 else {
            throw OpenSessionError.invalidLength(expectedAtLeast: 32, actual: packet.count)
        }
        guard (packet[5] & 0x3F) == 0x00 else {
            throw OpenSessionError.nonZeroStatus(packet[5])
        }

        guard let consoleSID = consoleSessionID, let managedSID = managedSystemSessionID else {
            throw IPMIError.notConnected
        }
        let responseSessionID = u32le(packet, 6)
        guard responseSessionID == consoleSID || responseSessionID == managedSID else {
            throw IPMIError.unsupported(
                String(
                    format: "unexpected session id in response: got=0x%08X console=0x%08X managed=0x%08X",
                    responseSessionID,
                    consoleSID,
                    managedSID
                )
            )
        }

        guard let keys = sessionKeys else { throw IPMIError.notConnected }

        let payloadLength = Int(packet[14]) | (Int(packet[15]) << 8)
        let payloadStart = 16
        let payloadEnd = payloadStart + payloadLength
        let authCodeLength = integrityAuthCodeLength(algorithm: negotiatedIntegrityAlgorithm)
        guard packet.count >= payloadEnd + 2 + authCodeLength else {
            throw OpenSessionError.invalidLength(expectedAtLeast: payloadEnd + 2 + authCodeLength, actual: packet.count)
        }

        let authStart = packet.count - authCodeLength
        let nextHeaderIndex = authStart - 1
        let padLengthIndex = authStart - 2
        let nextHeader = packet[nextHeaderIndex]
        guard nextHeader == 0x07 else {
            throw IPMIError.unsupported("invalid next header in RMCP+ trailer")
        }

        let integrityPadLength = Int(packet[padLengthIndex])
        let trailerStart = authStart - 2 - integrityPadLength
        guard trailerStart >= payloadEnd else {
            throw OpenSessionError.invalidLength(expectedAtLeast: payloadEnd, actual: trailerStart)
        }

        let signedBytes = Array(packet[4..<authStart])
        let expectedAuth = integrityAuthCode(key: keys.k1, payload: signedBytes, algorithm: negotiatedIntegrityAlgorithm)
        let actualAuth = Array(packet[authStart..<packet.count])
        guard expectedAuth == actualAuth else {
            throw IPMIError.unsupported("RMCP+ response integrity check failed")
        }

        let encryptedPayload = Array(packet[payloadStart..<payloadEnd])
        let decryptedPayload = try decryptIPMIPayload(encryptedPayload, aesKey: Array(keys.k2.prefix(16)))
        return try parseIPMIv15ResponsePayload(decryptedPayload)
    }

    private func buildIPMIMessagePayload(_ request: IPMIRequest) -> [UInt8] {
        let rsAddr: UInt8 = 0x20
        let netFnLun: UInt8 = (request.netFn << 2) | 0x00
        let rqAddr: UInt8 = 0x81
        let rqSeqLun: UInt8 = ((requestSequence & 0x3F) << 2) | 0x00
        requestSequence &+= 1

        var ipmi: [UInt8] = [
            rsAddr,
            netFnLun,
            checksum([rsAddr, netFnLun]),
            rqAddr,
            rqSeqLun,
            request.command
        ]
        ipmi.append(contentsOf: request.data)
        ipmi.append(checksum([rqAddr, rqSeqLun, request.command] + request.data))
        return ipmi
    }

    private func parseIPMIv15ResponsePayload(_ payload: [UInt8]) throws -> IPMIResponse {
        guard payload.count >= 8 else {
            throw OpenSessionError.invalidLength(expectedAtLeast: 8, actual: payload.count)
        }
        let completionCode = payload[6]
        let dataStart = 7
        let dataEnd = max(dataStart, payload.count - 1)
        let data = dataStart < dataEnd ? Array(payload[dataStart..<dataEnd]) : []
        return IPMIResponse(completionCode: completionCode, data: data)
    }

    private func encryptIPMIPayload(_ ipmiPayload: [UInt8], aesKey: [UInt8]) throws -> [UInt8] {
        let iv = (0..<16).map { _ in UInt8.random(in: 0...255) }
        let blockSize = 16
        let remainder = ipmiPayload.count % blockSize
        let padLength = remainder == 0 ? (blockSize - 1) : (blockSize - remainder - 1)
        var plain = ipmiPayload
        if padLength > 0 {
            plain.append(contentsOf: (1...padLength).map { UInt8($0) })
        }
        plain.append(UInt8(padLength))

        let cipher = try aesCBC128Encrypt(plain, key: aesKey, iv: iv)
        return iv + cipher
    }

    private func decryptIPMIPayload(_ encryptedPayload: [UInt8], aesKey: [UInt8]) throws -> [UInt8] {
        guard encryptedPayload.count >= 16 else {
            throw OpenSessionError.invalidLength(expectedAtLeast: 16, actual: encryptedPayload.count)
        }
        let iv = Array(encryptedPayload.prefix(16))
        let cipherText = Array(encryptedPayload.dropFirst(16))
        guard !cipherText.isEmpty, cipherText.count % 16 == 0 else {
            throw IPMIError.unsupported("invalid encrypted payload length")
        }

        let plain = try aesCBC128Decrypt(cipherText, key: aesKey, iv: iv)
        guard let padLengthByte = plain.last else {
            throw IPMIError.unsupported("empty decrypted payload")
        }
        let padLength = Int(padLengthByte)
        guard padLength <= plain.count - 1 else {
            throw IPMIError.unsupported("invalid encryption padding")
        }

        let payloadCount = plain.count - 1 - padLength
        guard payloadCount >= 0 else {
            throw IPMIError.unsupported("invalid decrypted payload length")
        }
        return Array(plain.prefix(payloadCount))
    }

    private func integrityAuthCodeLength(algorithm: RAKPAuthAlgorithm) -> Int {
        switch algorithm {
        case .hmacSHA1:
            return 12
        case .hmacSHA256:
            return 16
        }
    }

    private func integrityAuthCode(key: [UInt8], payload: [UInt8], algorithm: RAKPAuthAlgorithm) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: Data(key))
        switch algorithm {
        case .hmacSHA1:
            let mac = HMAC<Insecure.SHA1>.authenticationCode(for: Data(payload), using: symmetricKey)
            return Array(mac.prefix(12))
        case .hmacSHA256:
            let mac = HMAC<SHA256>.authenticationCode(for: Data(payload), using: symmetricKey)
            return Array(mac.prefix(16))
        }
    }

    private func aesCBC128Encrypt(_ plaintext: [UInt8], key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        guard key.count == 16, iv.count == 16 else {
            throw IPMIError.unsupported("invalid AES-128 key/iv length")
        }
        var output = Array(repeating: UInt8(0), count: plaintext.count + kCCBlockSizeAES128)
        let outputCapacity = output.count
        var outLength: size_t = 0

        let status = key.withUnsafeBytes { keyPtr in
            iv.withUnsafeBytes { ivPtr in
                plaintext.withUnsafeBytes { plainPtr in
                    output.withUnsafeMutableBytes { outPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            plainPtr.baseAddress, plaintext.count,
                            outPtr.baseAddress, outputCapacity,
                            &outLength
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw IPMIError.unsupported("AES-CBC encryption failed: \(status)")
        }
        return Array(output.prefix(outLength))
    }

    private func aesCBC128Decrypt(_ ciphertext: [UInt8], key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        guard key.count == 16, iv.count == 16 else {
            throw IPMIError.unsupported("invalid AES-128 key/iv length")
        }
        var output = Array(repeating: UInt8(0), count: ciphertext.count + kCCBlockSizeAES128)
        let outputCapacity = output.count
        var outLength: size_t = 0

        let status = key.withUnsafeBytes { keyPtr in
            iv.withUnsafeBytes { ivPtr in
                ciphertext.withUnsafeBytes { cipherPtr in
                    output.withUnsafeMutableBytes { outPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            cipherPtr.baseAddress, ciphertext.count,
                            outPtr.baseAddress, outputCapacity,
                            &outLength
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw IPMIError.unsupported("AES-CBC decryption failed: \(status)")
        }
        return Array(output.prefix(outLength))
    }

    private func buildIPMIv15RequestPacket(_ request: IPMIRequest) -> [UInt8] {
        let rsAddr: UInt8 = 0x20
        let netFnLun: UInt8 = (request.netFn << 2) | 0x00
        let rqAddr: UInt8 = 0x81
        let rqSeqLun: UInt8 = ((requestSequence & 0x3F) << 2) | 0x00
        requestSequence &+= 1

        var ipmi: [UInt8] = [
            rsAddr,
            netFnLun,
            checksum([rsAddr, netFnLun]),
            rqAddr,
            rqSeqLun,
            request.command
        ]
        ipmi.append(contentsOf: request.data)
        ipmi.append(checksum([rqAddr, rqSeqLun, request.command] + request.data))

        let rmcp: [UInt8] = [0x06, 0x00, 0xFF, 0x07]
        let authType: UInt8 = 0x00
        let sequenceNumber: [UInt8] = [0x00, 0x00, 0x00, 0x00]
        let sessionID: [UInt8] = [0x00, 0x00, 0x00, 0x00]
        return rmcp + [authType] + sequenceNumber + sessionID + [UInt8(ipmi.count)] + ipmi
    }

    private func parseIPMIv15ResponsePacket(_ packet: [UInt8]) throws -> IPMIResponse {
        guard packet.count >= 23 else {
            throw OpenSessionError.invalidLength(expectedAtLeast: 23, actual: packet.count)
        }

        let payloadLength = Int(packet[13])
        let payloadStart = 14
        let payloadEnd = payloadStart + payloadLength
        guard payloadEnd <= packet.count, payloadLength >= 8 else {
            throw OpenSessionError.invalidLength(expectedAtLeast: payloadStart + 8, actual: packet.count)
        }

        let payload = Array(packet[payloadStart..<payloadEnd])
        let completionCode = payload[6]
        let dataStart = 7
        let dataEnd = max(dataStart, payload.count - 1)
        let data = dataStart < dataEnd ? Array(payload[dataStart..<dataEnd]) : []
        return IPMIResponse(completionCode: completionCode, data: data)
    }

    private func openLoopbackMock(requestedPrivilege: PrivilegeLevel) async throws {
        let openSessionRequest = OpenSessionRequest(
            messageTag: 0,
            requestedMaximumPrivilegeLevel: requestedPrivilege,
            consoleSessionID: 0xA0A2A3A4,
            authenticationAlgorithm: 0x01,
            integrityAlgorithm: 0x01,
            confidentialityAlgorithm: 0x01
        )

        let openRequestBytes = openSessionRequest.encode()
        logger.logHexDump(prefix: ">> OPEN SESSION REQUEST", bytes: openRequestBytes)

        let openSessionResponseBytes = [
            openSessionRequest.messageTag,
            0x00,
            UInt8(requestedPrivilege.rawValue),
            0x00
        ]
            + Endian.u32le(openSessionRequest.consoleSessionID)
            + Endian.u32le(0x11223344)
            + [0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00]
            + [0x01, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00]
            + [0x02, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00]

        let openResponse = try OpenSessionResponse.decode(openSessionResponseBytes)
        guard openResponse.statusCode == 0 else {
            throw OpenSessionError.nonZeroStatus(openResponse.statusCode)
        }

        let consoleRandom = Array(UInt8(0x10)...UInt8(0x1F))
        let bmcRandom = Array(UInt8(0x20)...UInt8(0x2F))
        let bmcGUID = Array(UInt8(0x30)...UInt8(0x3F))

        let context = RAKPContext(
            consoleSessionID: openResponse.consoleSessionID,
            managedSystemSessionID: openResponse.managedSystemSessionID,
            consoleRandom: consoleRandom,
            managedSystemRandom: bmcRandom,
            managedSystemGUID: bmcGUID,
            requestedPrivilegeLevel: requestedPrivilege,
            username: username
        )

        let rakp1 = RAKPMessage1(
            messageTag: openSessionRequest.messageTag,
            managedSystemSessionID: context.managedSystemSessionID,
            consoleRandom: context.consoleRandom,
            requestedPrivilegeLevel: context.requestedPrivilegeLevel,
            username: context.username
        )
        logger.logHexDump(prefix: ">> RAKP1 MESSAGE", bytes: rakp1.encode())

        let rakp2AuthCode = RAKP.computeRAKP2AuthCode(context: context, password: password)
        let rakp2Bytes = [rakp1.messageTag, 0x00, 0x00, 0x00]
            + Endian.u32le(context.consoleSessionID)
            + context.managedSystemRandom
            + context.managedSystemGUID
            + rakp2AuthCode

        let rakp2 = try RAKPMessage2.decode(rakp2Bytes)
        guard rakp2.statusCode == 0 else {
            throw RAKPError.nonZeroStatus(rakp2.statusCode)
        }

        let expectedRAKP2 = RAKP.computeRAKP2AuthCode(context: context, password: password)
        guard rakp2.keyExchangeAuthCode == expectedRAKP2 else {
            throw RAKPError.authCodeMismatch
        }

        let rakp3AuthCode = RAKP.computeRAKP3AuthCode(context: context, password: password)
        let rakp3 = RAKPMessage3(
            messageTag: rakp2.messageTag,
            statusCode: 0,
            managedSystemSessionID: context.managedSystemSessionID,
            keyExchangeAuthCode: rakp3AuthCode
        )
        logger.logHexDump(prefix: ">> RAKP3 MESSAGE", bytes: rakp3.encode())

        let keys = RAKP.deriveKeys(context: context, password: password)
        let rakp4Integrity = RAKP.computeRAKP4IntegrityCheck(context: context, sik: keys.sik)
        let rakp4Bytes = [rakp3.messageTag, 0x00, 0x00, 0x00]
            + Endian.u32le(context.consoleSessionID)
            + rakp4Integrity

        let rakp4 = try RAKPMessage4.decode(rakp4Bytes)
        guard rakp4.statusCode == 0 else {
            throw RAKPError.nonZeroStatus(rakp4.statusCode)
        }

        let expectedRAKP4 = RAKP.computeRAKP4IntegrityCheck(context: context, sik: keys.sik)
        guard rakp4.integrityCheckValue == expectedRAKP4 else {
            throw RAKPError.integrityMismatch
        }

        _ = cipherSuiteID
        consoleSessionID = context.consoleSessionID
        managedSystemSessionID = context.managedSystemSessionID
        connected = true

        negotiatedPrivilege = privilege

        logger.log("IPMIv2 / RMCP+ SESSION OPENED SUCCESSFULLY")
    }

    private func u32le(_ bytes: [UInt8], _ start: Int) -> UInt32 {
        UInt32(bytes[start])
            | (UInt32(bytes[start + 1]) << 8)
            | (UInt32(bytes[start + 2]) << 16)
            | (UInt32(bytes[start + 3]) << 24)
    }

    private func isLoopbackHost(_ host: String) -> Bool {
        host == "127.0.0.1" || host == "localhost" || host == "::1"
    }
}
