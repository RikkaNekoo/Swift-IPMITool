import Testing
@testable import SwiftIPMI

@Suite struct RAKPTests {
    @Test func passwordKeyPadsTo20Bytes() {
        let key = RAKP.passwordKey("abc")
        #expect(key.count == 20)
        #expect(Array(key.prefix(3)) == Array("abc".utf8))
        #expect(key[3] == 0x00)
    }

    @Test func rakpRoundtripLoopbackFlowProducesVerifiableAuthCodes() throws {
        let context = RAKPContext(
            consoleSessionID: 0xA0A2A3A4,
            managedSystemSessionID: 0x11223344,
            consoleRandom: Array(UInt8(0x10)...UInt8(0x1F)),
            managedSystemRandom: Array(UInt8(0x20)...UInt8(0x2F)),
            managedSystemGUID: Array(UInt8(0x30)...UInt8(0x3F)),
            requestedPrivilegeLevel: .administrator,
            username: "root"
        )

        let auth2 = RAKP.computeRAKP2AuthCode(context: context, password: "calvin")
        #expect(auth2.count == 32)

        let auth3 = RAKP.computeRAKP3AuthCode(context: context, password: "calvin")
        #expect(auth3.count == 32)

        let keys = RAKP.deriveKeys(context: context, password: "calvin")
        #expect(keys.sik.count == 32)
        #expect(keys.k1.count == 32)
        #expect(keys.k2.count == 32)
        #expect(keys.sik != keys.k1)
        #expect(keys.k1 != keys.k2)

        let check4 = RAKP.computeRAKP4IntegrityCheck(context: context, sik: keys.sik)
        #expect(check4.count == 12)

        let m2Bytes = [UInt8(0x00), 0x00, 0x00, 0x00]
            + Endian.u32le(context.consoleSessionID)
            + context.managedSystemRandom
            + context.managedSystemGUID
            + auth2
        let m2 = try RAKPMessage2.decode(m2Bytes)
        #expect(m2.statusCode == 0x00)
        #expect(m2.keyExchangeAuthCode == auth2)

        let m3 = RAKPMessage3(
            messageTag: 0x00,
            statusCode: 0x00,
            managedSystemSessionID: context.managedSystemSessionID,
            keyExchangeAuthCode: auth3
        )
        let m3Encoded = m3.encode()
        #expect(m3Encoded.count == 40)

        let m4Bytes = [UInt8(0x00), 0x00, 0x00, 0x00]
            + Endian.u32le(context.consoleSessionID)
            + check4
        let m4 = try RAKPMessage4.decode(m4Bytes)
        #expect(m4.statusCode == 0x00)
        #expect(m4.integrityCheckValue == check4)
    }
}
