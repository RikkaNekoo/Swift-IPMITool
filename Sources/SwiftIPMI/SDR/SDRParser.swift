import Foundation

public enum SDRParserError: Error, Sendable, Equatable {
    case dataTooShort
    case invalidRecordLength(expected: Int, actual: Int)
}

public enum SDRParser {
    public static func parseRecord(_ bytes: [UInt8]) throws -> SDRRecord {
        guard bytes.count >= 5 else {
            throw SDRParserError.dataTooShort
        }

        let recordID = UInt16(bytes[0]) | (UInt16(bytes[1]) << 8)
        let sdrVersion = bytes[2]
        let recordType = bytes[3]
        let recordLength = bytes[4]
        let expectedLength = 5 + Int(recordLength)

        guard bytes.count >= expectedLength else {
            throw SDRParserError.invalidRecordLength(expected: expectedLength, actual: bytes.count)
        }

        let payload = Array(bytes[5..<expectedLength])
        let key = SDRCommonKey(
            recordID: recordID,
            sdrVersion: sdrVersion,
            recordType: recordType,
            recordLength: recordLength
        )

        switch recordType {
        case SDRRecordType.fullSensor.rawValue:
            return .full(parseFull(key: key, payload: payload))
        case SDRRecordType.compactSensor.rawValue:
            return .compact(parseCompact(key: key, payload: payload))
        case SDRRecordType.eventOnlySensor.rawValue:
            return .eventOnly(parseEventOnly(key: key, payload: payload))
        default:
            return .unsupported(rawType: recordType, key: key, payload: payload)
        }
    }

    private static func parseFull(key: SDRCommonKey, payload: [UInt8]) -> FullSensorRecord {
        let ownerID = payload[safe: 0] ?? 0x00
        let ownerLUN = payload[safe: 1] ?? 0x00
        let sensorNumber = payload[safe: 2] ?? 0x00
        let entityID = payload[safe: 3] ?? 0x00
        let entityInstance = payload[safe: 4] ?? 0x00
        let sensorType = payload[safe: 7] ?? 0x00
        let eventReadingTypeCode = payload[safe: 8] ?? 0x00

        let unit1 = payload[safe: 15] ?? 0x00
        let unitAnalogFormat = (unit1 >> 6) & 0x03
        let unitRate = (unit1 >> 3) & 0x07
        let unitModifier = (unit1 >> 1) & 0x03
        let unitIsPercent = (unit1 & 0x01) != 0
        let baseUnit = payload[safe: 16] ?? 0x00
        let modifierUnit = payload[safe: 17] ?? 0x00

        let linearization = payload[safe: 18] ?? 0x00
        let mTol = u16LE(payload, 19)
        let bAcc = u32LE(payload, 21)

        let thresholds = SensorRawThresholds(
            lnr: payload[safe: 31] ?? 0x00,
            lcr: payload[safe: 32] ?? 0x00,
            lnc: payload[safe: 33] ?? 0x00,
            unc: payload[safe: 36] ?? 0x00,
            ucr: payload[safe: 35] ?? 0x00,
            unr: payload[safe: 34] ?? 0x00
        )

        let idCode = payload[safe: 42] ?? 0x00
        let sensorID = parseIDString(idCode: idCode, bytes: payload, start: 43, fallbackPayload: payload)

        return FullSensorRecord(
            key: key,
            ownerID: ownerID,
            ownerLUN: ownerLUN,
            sensorNumber: sensorNumber,
            entityID: entityID,
            entityInstance: entityInstance,
            sensorType: sensorType,
            eventReadingTypeCode: eventReadingTypeCode,
            unitAnalogFormat: unitAnalogFormat,
            unitRate: unitRate,
            unitModifier: unitModifier,
            unitIsPercent: unitIsPercent,
            baseUnit: baseUnit,
            modifierUnit: modifierUnit,
            linearization: linearization,
            mTol: mTol,
            bAcc: bAcc,
            thresholds: thresholds,
            sensorID: sensorID
        )
    }

    private static func parseCompact(key: SDRCommonKey, payload: [UInt8]) -> CompactSensorRecord {
        let ownerID = payload[safe: 0] ?? 0x00
        let ownerLUN = payload[safe: 1] ?? 0x00
        let sensorNumber = payload[safe: 2] ?? 0x00
        let entityID = payload[safe: 3] ?? 0x00
        let entityInstance = payload[safe: 4] ?? 0x00
        let sensorType = payload[safe: 7] ?? 0x00
        let eventReadingTypeCode = payload[safe: 8] ?? 0x00
        let idCode = payload[safe: 26] ?? 0x00
        let sensorID = parseIDString(idCode: idCode, bytes: payload, start: 27, fallbackPayload: payload)

        return CompactSensorRecord(
            key: key,
            ownerID: ownerID,
            ownerLUN: ownerLUN,
            sensorNumber: sensorNumber,
            entityID: entityID,
            entityInstance: entityInstance,
            sensorType: sensorType,
            eventReadingTypeCode: eventReadingTypeCode,
            sensorID: sensorID
        )
    }

    private static func parseEventOnly(key: SDRCommonKey, payload: [UInt8]) -> EventOnlySensorRecord {
        let ownerID = payload[safe: 0] ?? 0x00
        let ownerLUN = payload[safe: 1] ?? 0x00
        let sensorNumber = payload[safe: 2] ?? 0x00
        let entityID = payload[safe: 3] ?? 0x00
        let entityInstance = payload[safe: 4] ?? 0x00
        let sensorType = payload[safe: 5] ?? 0x00
        let eventReadingTypeCode = payload[safe: 6] ?? 0x00
        let idCode = payload[safe: 15] ?? 0x00
        let sensorID = parseIDString(idCode: idCode, bytes: payload, start: 16, fallbackPayload: payload)

        return EventOnlySensorRecord(
            key: key,
            ownerID: ownerID,
            ownerLUN: ownerLUN,
            sensorNumber: sensorNumber,
            entityID: entityID,
            entityInstance: entityInstance,
            sensorType: sensorType,
            eventReadingTypeCode: eventReadingTypeCode,
            sensorID: sensorID
        )
    }

    private static func parseIDString(idCode: UInt8, bytes: [UInt8], start: Int, fallbackPayload: [UInt8]) -> String {
        let idLength = Int(idCode & 0x1F)
        if idLength > 0, start >= 0, bytes.count >= start + idLength {
            var idBytes = Array(bytes[start..<(start + idLength)])
            if let zero = idBytes.firstIndex(of: 0x00) {
                idBytes = Array(idBytes[..<zero])
            }
            if let value = String(bytes: idBytes, encoding: .ascii)?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty {
                return value
            }
            if let value = String(bytes: idBytes, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty {
                return value
            }
        }
        return parseLegacyIDString(fallbackPayload)
    }

    private static func parseLegacyIDString(_ payload: [UInt8]) -> String {
        if let last = payload.last {
            let idLength = Int(last & 0x1F)
            if idLength > 0, payload.count >= idLength + 1 {
                let start = payload.count - 1 - idLength
                var idBytes = Array(payload[start..<(payload.count - 1)])
                if let zero = idBytes.firstIndex(of: 0x00) {
                    idBytes = Array(idBytes[..<zero])
                }
                if let value = String(bytes: idBytes, encoding: .ascii)?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty {
                    return value
                }
                if let value = String(bytes: idBytes, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty {
                    return value
                }
            }
        }
        return ""
    }

    private static func u16LE(_ bytes: [UInt8], _ start: Int) -> UInt16 {
        guard let b0 = bytes[safe: start], let b1 = bytes[safe: start + 1] else { return 0 }
        return UInt16(b0) | (UInt16(b1) << 8)
    }

    private static func u32LE(_ bytes: [UInt8], _ start: Int) -> UInt32 {
        guard
            let b0 = bytes[safe: start],
            let b1 = bytes[safe: start + 1],
            let b2 = bytes[safe: start + 2],
            let b3 = bytes[safe: start + 3]
        else { return 0 }
        return UInt32(b0) | (UInt32(b1) << 8) | (UInt32(b2) << 16) | (UInt32(b3) << 24)
    }
}

private extension Array where Element == UInt8 {
    subscript(safe index: Int) -> UInt8? {
        guard indices.contains(index) else { return nil }
        return self[index]
    }
}
