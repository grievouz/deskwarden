import Foundation

/// Splits a byte stream into frames: a 4-byte big-endian length, then that
/// many bytes of payload.
struct FrameDecoder {
    static let maxFrameSize = 1 << 20

    struct FrameTooLarge: Error {
        let size: Int
    }

    private var buffer = Data()

    mutating func append(_ data: Data) {
        buffer.append(data)
    }

    mutating func nextFrame() throws -> Data? {
        guard buffer.count >= 4 else { return nil }
        let size = buffer.prefix(4).reduce(0) { $0 << 8 | Int($1) }
        guard size <= Self.maxFrameSize else { throw FrameTooLarge(size: size) }
        guard buffer.count >= 4 + size else { return nil }
        let frame = Data(buffer.dropFirst(4).prefix(size))
        buffer = Data(buffer.dropFirst(4 + size))
        return frame
    }

    static func encode(_ payload: Data) -> Data {
        let size = UInt32(payload.count)
        var frame = Data([UInt8(size >> 24), UInt8(size >> 16 & 0xFF), UInt8(size >> 8 & 0xFF), UInt8(size & 0xFF)])
        frame.append(payload)
        return frame
    }
}
