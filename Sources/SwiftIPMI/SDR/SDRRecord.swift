import Foundation

public enum SDRRecordType: UInt8, Sendable, Equatable {
    case fullSensor = 0x01
    case compactSensor = 0x02
    case eventOnlySensor = 0x03
}

public struct SDRCommonKey: Sendable, Equatable {
    public let recordID: UInt16
    public let sdrVersion: UInt8
    public let recordType: UInt8
    public let recordLength: UInt8

    public init(recordID: UInt16, sdrVersion: UInt8, recordType: UInt8, recordLength: UInt8) {
        self.recordID = recordID
        self.sdrVersion = sdrVersion
        self.recordType = recordType
        self.recordLength = recordLength
    }
}

public struct SensorRawThresholds: Sendable, Equatable {
    public let lnr: UInt8
    public let lcr: UInt8
    public let lnc: UInt8
    public let unc: UInt8
    public let ucr: UInt8
    public let unr: UInt8

    public init(lnr: UInt8, lcr: UInt8, lnc: UInt8, unc: UInt8, ucr: UInt8, unr: UInt8) {
        self.lnr = lnr
        self.lcr = lcr
        self.lnc = lnc
        self.unc = unc
        self.ucr = ucr
        self.unr = unr
    }
}

public struct FullSensorRecord: Sendable, Equatable {
    public let key: SDRCommonKey
    public let ownerID: UInt8
    public let ownerLUN: UInt8
    public let sensorNumber: UInt8
    public let entityID: UInt8
    public let entityInstance: UInt8
    public let sensorType: UInt8
    public let eventReadingTypeCode: UInt8
    public let unitAnalogFormat: UInt8
    public let unitRate: UInt8
    public let unitModifier: UInt8
    public let unitIsPercent: Bool
    public let baseUnit: UInt8
    public let modifierUnit: UInt8
    public let linearization: UInt8
    public let mTol: UInt16
    public let bAcc: UInt32
    public let thresholds: SensorRawThresholds
    public let sensorID: String

    public init(
        key: SDRCommonKey,
        ownerID: UInt8,
        ownerLUN: UInt8,
        sensorNumber: UInt8,
        entityID: UInt8,
        entityInstance: UInt8,
        sensorType: UInt8,
        eventReadingTypeCode: UInt8,
        unitAnalogFormat: UInt8,
        unitRate: UInt8,
        unitModifier: UInt8,
        unitIsPercent: Bool,
        baseUnit: UInt8,
        modifierUnit: UInt8,
        linearization: UInt8,
        mTol: UInt16,
        bAcc: UInt32,
        thresholds: SensorRawThresholds,
        sensorID: String
    ) {
        self.key = key
        self.ownerID = ownerID
        self.ownerLUN = ownerLUN
        self.sensorNumber = sensorNumber
        self.entityID = entityID
        self.entityInstance = entityInstance
        self.sensorType = sensorType
        self.eventReadingTypeCode = eventReadingTypeCode
        self.unitAnalogFormat = unitAnalogFormat
        self.unitRate = unitRate
        self.unitModifier = unitModifier
        self.unitIsPercent = unitIsPercent
        self.baseUnit = baseUnit
        self.modifierUnit = modifierUnit
        self.linearization = linearization
        self.mTol = mTol
        self.bAcc = bAcc
        self.thresholds = thresholds
        self.sensorID = sensorID
    }
}

public struct CompactSensorRecord: Sendable, Equatable {
    public let key: SDRCommonKey
    public let ownerID: UInt8
    public let ownerLUN: UInt8
    public let sensorNumber: UInt8
    public let entityID: UInt8
    public let entityInstance: UInt8
    public let sensorType: UInt8
    public let eventReadingTypeCode: UInt8
    public let sensorID: String

    public init(
        key: SDRCommonKey,
        ownerID: UInt8,
        ownerLUN: UInt8,
        sensorNumber: UInt8,
        entityID: UInt8,
        entityInstance: UInt8,
        sensorType: UInt8,
        eventReadingTypeCode: UInt8,
        sensorID: String
    ) {
        self.key = key
        self.ownerID = ownerID
        self.ownerLUN = ownerLUN
        self.sensorNumber = sensorNumber
        self.entityID = entityID
        self.entityInstance = entityInstance
        self.sensorType = sensorType
        self.eventReadingTypeCode = eventReadingTypeCode
        self.sensorID = sensorID
    }
}

public struct EventOnlySensorRecord: Sendable, Equatable {
    public let key: SDRCommonKey
    public let ownerID: UInt8
    public let ownerLUN: UInt8
    public let sensorNumber: UInt8
    public let entityID: UInt8
    public let entityInstance: UInt8
    public let sensorType: UInt8
    public let eventReadingTypeCode: UInt8
    public let sensorID: String

    public init(
        key: SDRCommonKey,
        ownerID: UInt8,
        ownerLUN: UInt8,
        sensorNumber: UInt8,
        entityID: UInt8,
        entityInstance: UInt8,
        sensorType: UInt8,
        eventReadingTypeCode: UInt8,
        sensorID: String
    ) {
        self.key = key
        self.ownerID = ownerID
        self.ownerLUN = ownerLUN
        self.sensorNumber = sensorNumber
        self.entityID = entityID
        self.entityInstance = entityInstance
        self.sensorType = sensorType
        self.eventReadingTypeCode = eventReadingTypeCode
        self.sensorID = sensorID
    }
}

public enum SDRRecord: Sendable, Equatable {
    case full(FullSensorRecord)
    case compact(CompactSensorRecord)
    case eventOnly(EventOnlySensorRecord)
    case unsupported(rawType: UInt8, key: SDRCommonKey, payload: [UInt8])
}
