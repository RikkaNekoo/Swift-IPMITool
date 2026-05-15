import Testing
@testable import SwiftIPMI

@Suite struct RawCommandTests {
    @Test func formattedOutputWrapsAt16BytesPerLine() {
        let bytes: [UInt8] = Array(0x00...0x13)
        let response = RawResponse(completionCode: 0x00, data: bytes)

        let expected = [
            " 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f",
            " 10 11 12 13"
        ].joined(separator: "\n")

        #expect(response.formattedOutput() == expected)
    }

    @Test func formattedOutputReturnsEmptyStringWhenSuccessHasNoPayload() {
        let response = RawResponse(completionCode: 0x00, data: [])
        #expect(response.formattedOutput().isEmpty)
    }

    @Test func formattedOutputShowsCompletionCodeWhenNonZero() {
        let response = RawResponse(completionCode: 0xC1, data: [0xAA, 0xBB])
        #expect(response.formattedOutput() == "Unable to send RAW command (ccode: 0xc1)")
    }
}
