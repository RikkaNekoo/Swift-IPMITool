import Foundation

public enum IPMIError: Error, Sendable {
    case notConnected
    case commandFailed(UInt8)
    case unsupported(String)
}

public actor IPMIClient {
    private enum SensorCommandCode {
        static let getSensorReading: UInt8 = 0x2D
        static let getSensorThresholds: UInt8 = 0x27
    }

    private struct SensorMeta: Sendable {
        let name: String
        let sensorNumber: UInt8
        let eventReadingTypeCode: UInt8
        let full: FullSensorRecord?
    }

    private let session: LanPlusSession

    public init(
        host: String,
        port: UInt16 = 623,
        username: String,
        password: String,
        privilege: PrivilegeLevel = .administrator,
        cipherSuiteID: UInt8? = nil,
        timeout: TimeInterval = 2.0,
        retries: Int = 4,
        loggingEnabled: Bool = false
    ) {
        _ = (timeout, retries)
        self.session = LanPlusSession(
            host: host,
            port: port,
            username: username,
            password: password,
            privilege: privilege,
            cipherSuiteID: cipherSuiteID,
            loggingEnabled: loggingEnabled
        )
    }

    public func connect() async throws {
        try await session.open()
    }

    public func close() async {
        await session.close()
    }

    public func sensorList() async throws -> [SensorRow] {
        try await fetchDynamicSensorRows()
    }

    public func sensorListFormatted() async throws -> String {
        SensorCommand.render(rows: try await sensorList())
    }

    public func raw(netFn: UInt8, command: UInt8, data: [UInt8]) async throws -> RawResponse {
        let response = try await session.send(IPMIRequest(netFn: netFn, command: command, data: data))
        return RawResponse(completionCode: response.completionCode, data: response.data)
    }

    private func fetchDynamicSensorRows() async throws -> [SensorRow] {
        let repository = SDRRepository { [session] request in
            try await session.send(request)
        }

        let records = try await repository.fetchAllRecords()
        let metas = records.compactMap(sensorMeta(from:))
        guard !metas.isEmpty else { return [] }

        var rows: [SensorRow] = []
        rows.reserveCapacity(metas.count)
        for meta in metas {
            rows.append(try await fetchSensorRow(meta))
        }
        return rows
    }

    private func sensorMeta(from record: SDRRecord) -> SensorMeta? {
        switch record {
        case let .full(full):
            return SensorMeta(name: full.sensorID, sensorNumber: full.sensorNumber, eventReadingTypeCode: full.eventReadingTypeCode, full: full)
        case let .compact(compact):
            return SensorMeta(name: compact.sensorID, sensorNumber: compact.sensorNumber, eventReadingTypeCode: compact.eventReadingTypeCode, full: nil)
        case let .eventOnly(eventOnly):
            return SensorMeta(name: eventOnly.sensorID, sensorNumber: eventOnly.sensorNumber, eventReadingTypeCode: eventOnly.eventReadingTypeCode, full: nil)
        case .unsupported:
            return nil
        }
    }

    private func fetchSensorRow(_ meta: SensorMeta) async throws -> SensorRow {
        let response = try await session.send(IPMIRequest(
            netFn: NetFn.sensorEvent.rawValue,
            command: SensorCommandCode.getSensorReading,
            data: [meta.sensorNumber]
        ))

        guard response.completionCode == 0x00 else {
            return SensorRow(name: meta.name, valueKind: .unavailable, status: "na")
        }

        guard let reading = response.data.first else {
            return SensorRow(name: meta.name, valueKind: .unavailable, status: "na")
        }

        // 参考 ipmitool: data[1] 同时包含 Reading/Scanning 状态
        // bit5(0x20)=reading unavailable
        // bit6(0x40)=sensor scanning enabled（为 0 表示 disabled）
        let readingState = response.data.count >= 2 ? response.data[1] : 0
        let readingUnavailable = (readingState & 0x20) != 0
        let scanningDisabled = (readingState & 0x40) == 0
        if readingUnavailable || scanningDisabled {
            return SensorRow(name: meta.name, valueKind: .unavailable, status: "na")
        }

        let stateMsb = response.data.count >= 3 ? UInt16(response.data[2]) : 0
        let stateLsb = response.data.count >= 4 ? UInt16(response.data[3]) : 0
        let state = (stateMsb << 8) | stateLsb

        if isDiscrete(eventReadingTypeCode: meta.eventReadingTypeCode) {
            let status = String(format: "0x%04X", state)
            return SensorRow(name: meta.name, valueKind: .discrete(reading, state: state), status: status)
        }

        guard let full = meta.full else {
            return SensorRow(name: meta.name, valueKind: .analog(Double(reading), unit: ""), status: "ok")
        }

        if full.unitAnalogFormat == 0x03 {
            let status = String(format: "0x%04X", state)
            return SensorRow(name: meta.name, valueKind: .discrete(reading, state: state), status: status)
        }

        let unit = unitString(for: full)
        let converted = normalizeOEMReading(convertRawReading(reading, full: full), unit: unit)
        let thresholds = try await fetchThresholds(meta: meta, full: full, unit: unit)
        return SensorRow(name: meta.name, valueKind: .analog(converted, unit: unit), status: "ok", thresholds: thresholds)
    }

    private func fetchThresholds(meta: SensorMeta, full: FullSensorRecord, unit: String) async throws -> SensorThresholds {
        let response = try await session.send(IPMIRequest(
            netFn: NetFn.sensorEvent.rawValue,
            command: SensorCommandCode.getSensorThresholds,
            data: [meta.sensorNumber]
        ))
        guard response.completionCode == 0x00, response.data.count >= 7 else {
            return .init()
        }

        let mask = response.data[0]
        func threshold(_ bit: UInt8, _ idx: Int) -> Double? {
            guard (mask & bit) != 0, idx < response.data.count else { return nil }
            return normalizeOEMReading(convertRawReading(response.data[idx], full: full), unit: unit)
        }

        // 对齐 ipmitool/ipmi_sensor.h: LOWER_* 使用低 3 bit，UPPER_* 使用高 3 bit。
        // data 索引按 ipmitool/lib/ipmi_sensor.c 的 PTS(...)：
        // LNC->1, LCR->2, LNR->3, UNC->4, UCR->5, UNR->6
        return SensorThresholds(
            lnr: threshold(0x04, 3),
            lcr: threshold(0x02, 2),
            lnc: threshold(0x01, 1),
            unc: threshold(0x08, 4),
            ucr: threshold(0x10, 5),
            unr: threshold(0x20, 6)
        )
    }

    private func convertRawReading(_ raw: UInt8, full: FullSensorRecord) -> Double {
        let m = decodeM(full.mTol)
        let b = decodeB(full.bAcc)
        let k1 = decodeBExp(full.bAcc)
        let k2 = decodeRExp(full.bAcc)

        let rawValue = toSigned(raw, format: full.unitAnalogFormat)
        let linear = ((Double(m) * rawValue) + (Double(b) * pow(10.0, Double(k1)))) * pow(10.0, Double(k2))

        switch full.linearization & 0x7F {
        case 0x00: return linear
        case 0x01: return log(linear)
        case 0x02: return log10(linear)
        case 0x03: return log2(linear)
        case 0x04: return exp(linear)
        case 0x05: return pow(10.0, linear)
        case 0x06: return pow(2.0, linear)
        case 0x07: return linear == 0 ? 0 : 1.0 / linear
        case 0x08: return pow(linear, 2)
        case 0x09: return pow(linear, 3)
        case 0x0A: return sqrt(linear)
        case 0x0B: return cbrt(linear)
        default: return linear
        }
    }

    private func unitString(for full: FullSensorRecord) -> String {
        let base = unitName(full.baseUnit)
        if full.unitIsPercent && full.baseUnit == 0 { return "percent" }
        let pctPrefix = full.unitIsPercent ? "% " : ""
        let modifier = unitName(full.modifierUnit)
        switch full.unitModifier {
        case 1: return "\(pctPrefix)\(base)/\(modifier)"
        case 2: return "\(pctPrefix)\(base)*\(modifier)"
        default: return "\(pctPrefix)\(base)"
        }
    }

    private func unitName(_ code: UInt8) -> String {
        switch code {
        case 1: return "degrees C"
        case 4: return "Volts"
        case 5: return "Amps"
        case 6: return "Watts"
        case 18: return "RPM"
        default: return ""
        }
    }

    private func decodeM(_ mtol: UInt16) -> Int {
        let b0 = Int(mtol & 0x00FF)
        let b1 = Int((mtol >> 8) & 0x00FF)
        let value = (b0 | ((b1 & 0xC0) << 2)) & 0x03FF
        return signExtend(value, bits: 10)
    }

    private func decodeB(_ bacc: UInt32) -> Int {
        let b0 = Int(bacc & 0x000000FF)
        let b2 = Int((bacc >> 16) & 0x000000FF)
        let value = (b0 | ((b2 & 0xC0) << 2)) & 0x03FF
        return signExtend(value, bits: 10)
    }

    private func decodeBExp(_ bacc: UInt32) -> Int {
        let b3 = Int((bacc >> 24) & 0x000000FF)
        return signExtend(b3 & 0x0F, bits: 4)
    }

    private func decodeRExp(_ bacc: UInt32) -> Int {
        let b3 = Int((bacc >> 24) & 0x000000FF)
        return signExtend((b3 >> 4) & 0x0F, bits: 4)
    }

    private func signExtend(_ value: Int, bits: Int) -> Int {
        let sign = 1 << (bits - 1)
        return (value & sign) != 0 ? value - (1 << bits) : value
    }

    private func toSigned(_ raw: UInt8, format: UInt8) -> Double {
        switch format {
        case 1: // 1's complement (与 ipmitool: if (val & 0x80) val++; 然后按 int8 解释)
            if (raw & 0x80) != 0 {
                return Double(Int8(bitPattern: raw &+ 1))
            }
            return Double(raw)
        case 2: // 2's complement
            return Double(Int8(bitPattern: raw))
        default:
            return Double(raw)
        }
    }

    private func isDiscrete(eventReadingTypeCode: UInt8) -> Bool {
        eventReadingTypeCode >= 0x6F
    }

    /// iDRAC 上部分温度传感器存在 OEM 偏移：当读数处于异常高值区间时按 ipmitool 行为归一化。
    private func normalizeOEMReading(_ value: Double, unit: String) -> Double {
        if unit == "degrees C", value >= 200.0 {
            return value - 255.0
        }
        return value
    }
}
