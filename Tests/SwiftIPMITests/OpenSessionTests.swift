import Testing
@testable import SwiftIPMI

@Suite struct OpenSessionTests {
    @Test func openSessionRequestEncodingMatchesExpectedLayout() {
        let request = OpenSessionRequest(
            messageTag: 0,
            requestedMaximumPrivilegeLevel: .administrator,
            consoleSessionID: 0xA0A2A3A4,
            authenticationAlgorithm: 0x01,
            integrityAlgorithm: 0x01,
            confidentialityAlgorithm: 0x01
        )

        let encoded = request.encode()
        let expected: [UInt8] = [
            0x00, 0x04, 0x00, 0x00,
            0xA4, 0xA3, 0xA2, 0xA0,
            0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00
        ]

        #expect(encoded == expected)
    }

    @Test func openSessionResponseDecodeParsesFields() throws {
        let bytes: [UInt8] = [
            0x00, 0x00, 0x04, 0x00,
            0xA4, 0xA3, 0xA2, 0xA0,
            0x44, 0x33, 0x22, 0x11,
            0x00, 0x00, 0x00, 0x08,
            0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x08,
            0x01, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x08,
            0x01, 0x00, 0x00, 0x00
        ]

        let response = try OpenSessionResponse.decode(bytes)
        #expect(response.messageTag == 0x00)
        #expect(response.statusCode == 0x00)
        #expect(response.maximumPrivilegeLevel == 0x04)
        #expect(response.consoleSessionID == 0xA0A2A3A4)
        #expect(response.managedSystemSessionID == 0x11223344)
        #expect(response.authenticationAlgorithm == 0x01)
        #expect(response.integrityAlgorithm == 0x01)
        #expect(response.confidentialityAlgorithm == 0x01)
    }

    @Test func openSessionResponseDecodeRejectsShortPacket() {
        #expect(throws: OpenSessionError.self) {
            _ = try OpenSessionResponse.decode([0x00, 0x01])
        }
    }
}
