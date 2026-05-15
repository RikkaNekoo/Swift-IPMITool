import Testing
@testable import SwiftIPMI

@Suite struct SDRRepositoryTests {
    @Test func fetchAllRecordsWithChunkRetryAndFragmentAssembly() async throws {
        let backend = MockSDRBackend(responses: [
            .expect(command: 0x20, completionCode: 0x00, data: [0x01, 0x00]),
            .expect(command: 0x22, completionCode: 0x00, data: [0x66, 0x55]),
            .expect(command: 0x23, completionCode: 0xCA, data: []),
            .expect(command: 0x23, completionCode: 0x00, data: [
                0xFF, 0xFF,
                0x00, 0x10, 0x51, 0x03, 0x0A,
                0x20, 0x00, 0x44, 0x07
            ]),
            .expect(command: 0x23, completionCode: 0x00, data: [
                0xFF, 0xFF,
                0x01, 0x05, 0x6F, 0x45, 0x56, 0x02
            ])
        ])

        let repository = SDRRepository(initialChunkSize: 0x08) { request in
            try await backend.send(request)
        }

        let records = try await repository.fetchAllRecords()
        #expect(records.count == 1)

        guard case let .eventOnly(record) = records[0] else {
            Issue.record("expect event-only record")
            return
        }

        #expect(record.key.recordID == 0x1000)
        #expect(record.sensorNumber == 0x44)
        #expect(record.sensorID == "EV")

        let firstGet = try #require(await backend.request(at: 2))
        #expect(firstGet.data.last == 0x08)

        let secondGet = try #require(await backend.request(at: 3))
        #expect(secondGet.data.last == 0x04)
    }
}

private actor MockSDRBackend {
    struct PlannedResponse: Sendable {
        let command: UInt8
        let completionCode: UInt8
        let data: [UInt8]

        static func expect(command: UInt8, completionCode: UInt8, data: [UInt8]) -> PlannedResponse {
            PlannedResponse(command: command, completionCode: completionCode, data: data)
        }
    }

    enum Error: Swift.Error {
        case noMoreResponses
        case unexpectedCommand(expected: UInt8, got: UInt8)
    }

    private var responses: [PlannedResponse]
    private(set) var requests: [IPMIRequest] = []

    init(responses: [PlannedResponse]) {
        self.responses = responses
    }

    func send(_ request: IPMIRequest) throws -> IPMIResponse {
        requests.append(request)
        guard !responses.isEmpty else {
            throw Error.noMoreResponses
        }

        let next = responses.removeFirst()
        guard request.command == next.command else {
            throw Error.unexpectedCommand(expected: next.command, got: request.command)
        }

        return IPMIResponse(completionCode: next.completionCode, data: next.data)
    }

    func request(at index: Int) -> IPMIRequest? {
        guard requests.indices.contains(index) else { return nil }
        return requests[index]
    }
}
