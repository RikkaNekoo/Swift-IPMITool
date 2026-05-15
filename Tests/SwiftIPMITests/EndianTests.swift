import Testing
@testable import SwiftIPMI

@Suite struct EndianTests {
    @Test func littleEndianEncoders() {
        #expect(Endian.u16le(0x1234) == [0x34, 0x12])
        #expect(Endian.u32le(0x12345678) == [0x78, 0x56, 0x34, 0x12])
    }
}
