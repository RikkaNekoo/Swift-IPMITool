public enum Endian {
    public static func u16le(_ value: UInt16) -> [UInt8] {
        let v = value.littleEndian
        return [UInt8(truncatingIfNeeded: v), UInt8(truncatingIfNeeded: v >> 8)]
    }

    public static func u32le(_ value: UInt32) -> [UInt8] {
        let v = value.littleEndian
        return [
            UInt8(truncatingIfNeeded: v),
            UInt8(truncatingIfNeeded: v >> 8),
            UInt8(truncatingIfNeeded: v >> 16),
            UInt8(truncatingIfNeeded: v >> 24)
        ]
    }
}
