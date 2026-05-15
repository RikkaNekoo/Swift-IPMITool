import Testing
@testable import SwiftIPMI

@Suite struct SDRParserTests {
    @Test func parseFullRecord() throws {
        let payload: [UInt8] = [
            0x20, 0x00, 0x30, 0x07, 0x01, 0x00, 0x00,
            0x04, 0x01,
            0x00, 0x00, 0x00,
            0x46, 0x61, 0x6E, 0x31,
            0x04
        ]
        let bytes: [UInt8] = [
            0x34, 0x12,
            0x51,
            0x01,
            UInt8(payload.count)
        ] + payload

        let record = try SDRParser.parseRecord(bytes)

        guard case let .full(full) = record else {
            Issue.record("expect full record")
            return
        }

        #expect(full.key.recordID == 0x1234)
        #expect(full.key.recordType == 0x01)
        #expect(full.ownerID == 0x20)
        #expect(full.sensorNumber == 0x30)
        #expect(full.sensorType == 0x04)
        #expect(full.eventReadingTypeCode == 0x01)
        #expect(full.sensorID == "Fan1")
    }

    @Test func parseCompactRecord() throws {
        let payload: [UInt8] = [
            0x20, 0x00, 0x31, 0x07, 0x01, 0x00, 0x00,
            0x01, 0x6F,
            0x00,
            0x49, 0x44,
            0x02
        ]
        let bytes: [UInt8] = [0x35, 0x12, 0x51, 0x02, UInt8(payload.count)] + payload

        let record = try SDRParser.parseRecord(bytes)

        guard case let .compact(compact) = record else {
            Issue.record("expect compact record")
            return
        }

        #expect(compact.key.recordID == 0x1235)
        #expect(compact.sensorNumber == 0x31)
        #expect(compact.sensorType == 0x01)
        #expect(compact.eventReadingTypeCode == 0x6F)
        #expect(compact.sensorID == "ID")
    }

    @Test func parseEventOnlyRecord() throws {
        let payload: [UInt8] = [
            0x20, 0x00, 0x40, 0x07, 0x01,
            0x05, 0x6F,
            0x45, 0x56,
            0x02
        ]
        let bytes: [UInt8] = [0x36, 0x12, 0x51, 0x03, UInt8(payload.count)] + payload

        let record = try SDRParser.parseRecord(bytes)

        guard case let .eventOnly(eventOnly) = record else {
            Issue.record("expect event-only record")
            return
        }

        #expect(eventOnly.key.recordID == 0x1236)
        #expect(eventOnly.sensorNumber == 0x40)
        #expect(eventOnly.sensorType == 0x05)
        #expect(eventOnly.eventReadingTypeCode == 0x6F)
        #expect(eventOnly.sensorID == "EV")
    }

    @Test func parseUnsupportedRecordType() throws {
        let payload: [UInt8] = [0xAA, 0xBB]
        let bytes: [UInt8] = [0x01, 0x00, 0x51, 0x14, UInt8(payload.count)] + payload

        let record = try SDRParser.parseRecord(bytes)
        guard case let .unsupported(rawType, _, gotPayload) = record else {
            Issue.record("expect unsupported record")
            return
        }

        #expect(rawType == 0x14)
        #expect(gotPayload == payload)
    }
}
