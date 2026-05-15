import Foundation

public enum SDRError: Error, Sendable, Equatable {
    case malformedResponse(command: UInt8)
    case recordTooLarge
    case invalidRecordLength
    case completionCode(UInt8, command: UInt8)
}

public struct SDRRepositoryInfo: Sendable, Equatable {
    public let recordCount: UInt16

    public init(recordCount: UInt16) {
        self.recordCount = recordCount
    }
}

public actor SDRRepository {
    private enum Command {
        static let getRepositoryInfo: UInt8 = 0x20
        static let reserveRepository: UInt8 = 0x22
        static let getSDR: UInt8 = 0x23
    }

    private let sendRequest: @Sendable (IPMIRequest) async throws -> IPMIResponse
    private let initialChunkSize: UInt8

    public init(
        initialChunkSize: UInt8 = 0xFE,
        sendRequest: @escaping @Sendable (IPMIRequest) async throws -> IPMIResponse
    ) {
        self.initialChunkSize = initialChunkSize
        self.sendRequest = sendRequest
    }

    public func getRepositoryInfo() async throws -> SDRRepositoryInfo {
        let response = try await sendStorage(command: Command.getRepositoryInfo, data: [])
        guard response.data.count >= 2 else {
            throw SDRError.malformedResponse(command: Command.getRepositoryInfo)
        }

        let count = UInt16(response.data[0]) | (UInt16(response.data[1]) << 8)
        return SDRRepositoryInfo(recordCount: count)
    }

    public func reserveRepository() async throws -> UInt16 {
        let response = try await sendStorage(command: Command.reserveRepository, data: [])
        guard response.data.count >= 2 else {
            throw SDRError.malformedResponse(command: Command.reserveRepository)
        }

        return UInt16(response.data[0]) | (UInt16(response.data[1]) << 8)
    }

    public func fetchAllRecords() async throws -> [SDRRecord] {
        _ = try await getRepositoryInfo()
        let reservationID = try await reserveRepository()

        var records: [SDRRecord] = []
        var nextRecordID: UInt16 = 0x0000

        while nextRecordID != 0xFFFF {
            let fetched = try await fetchSingleRecord(
                reservationID: reservationID,
                recordID: nextRecordID
            )
            records.append(try SDRParser.parseRecord(fetched.recordBytes))
            nextRecordID = fetched.nextRecordID
        }

        return records
    }

    private func fetchSingleRecord(reservationID: UInt16, recordID: UInt16) async throws -> (nextRecordID: UInt16, recordBytes: [UInt8]) {
        var chunkSize = initialChunkSize
        var offset: UInt8 = 0x00
        var nextRecordID: UInt16 = 0xFFFF
        var recordBytes: [UInt8] = []

        while true {
            let requestData: [UInt8] = [
                UInt8(truncatingIfNeeded: reservationID & 0x00FF),
                UInt8(truncatingIfNeeded: reservationID >> 8),
                UInt8(truncatingIfNeeded: recordID & 0x00FF),
                UInt8(truncatingIfNeeded: recordID >> 8),
                offset,
                chunkSize
            ]

            let response = try await sendRequest(IPMIRequest(
                netFn: NetFn.storage.rawValue,
                command: Command.getSDR,
                data: requestData
            ))

            if response.completionCode == 0xCA {
                guard chunkSize > 0x01 else {
                    throw SDRError.completionCode(response.completionCode, command: Command.getSDR)
                }
                chunkSize = max(0x01, chunkSize / 2)
                continue
            }

            guard response.completionCode == 0x00 else {
                throw SDRError.completionCode(response.completionCode, command: Command.getSDR)
            }

            guard response.data.count >= 2 else {
                throw SDRError.malformedResponse(command: Command.getSDR)
            }

            nextRecordID = UInt16(response.data[0]) | (UInt16(response.data[1]) << 8)
            let fragment = Array(response.data.dropFirst(2))
            recordBytes.append(contentsOf: fragment)

            if recordBytes.count >= 5 {
                let expectedPayloadLength = Int(recordBytes[4])
                let expectedTotalLength = 5 + expectedPayloadLength
                guard expectedTotalLength <= 0x1FF else {
                    throw SDRError.recordTooLarge
                }
                if recordBytes.count >= expectedTotalLength {
                    recordBytes = Array(recordBytes.prefix(expectedTotalLength))
                    return (nextRecordID, recordBytes)
                }
            }

            let newOffset = Int(offset) + fragment.count
            guard newOffset <= 0xFF else {
                throw SDRError.invalidRecordLength
            }
            offset = UInt8(newOffset)

            if fragment.isEmpty {
                throw SDRError.invalidRecordLength
            }
        }
    }

    private func sendStorage(command: UInt8, data: [UInt8]) async throws -> IPMIResponse {
        let response = try await sendRequest(IPMIRequest(netFn: NetFn.storage.rawValue, command: command, data: data))
        guard response.completionCode == 0x00 else {
            throw SDRError.completionCode(response.completionCode, command: command)
        }
        return response
    }
}
