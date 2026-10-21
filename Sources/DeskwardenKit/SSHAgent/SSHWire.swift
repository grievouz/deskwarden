import Foundation

/// SSH wire encoding (RFC 4251): big-endian uint32s, length-prefixed strings
/// and two's-complement mpints.
struct SSHReader {
    struct Truncated: Error {}

    private let data: Data
    private var offset: Data.Index

    init(_ data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    var isAtEnd: Bool {
        offset >= data.endIndex
    }

    mutating func readByte() throws -> UInt8 {
        guard offset < data.endIndex else { throw Truncated() }
        defer { offset += 1 }
        return data[offset]
    }

    mutating func readUInt32() throws -> UInt32 {
        let bytes = try readBytes(4)
        return bytes.reduce(0) { $0 << 8 | UInt32($1) }
    }

    mutating func readString() throws -> Data {
        try readBytes(Int(readUInt32()))
    }

    mutating func readText() throws -> String {
        String(decoding: try readString(), as: UTF8.self)
    }

    /// An mpint's magnitude, without the sign byte OpenSSH adds when the high bit is set.
    mutating func readMPInt() throws -> Data {
        Data(try readString().drop { $0 == 0 })
    }

    mutating func readBytes(_ count: Int) throws -> Data {
        guard count >= 0, data.endIndex - offset >= count else { throw Truncated() }
        defer { offset += count }
        return Data(data[offset..<offset + count])
    }
}

struct SSHWriter {
    private(set) var data = Data()

    mutating func write(_ byte: UInt8) {
        data.append(byte)
    }

    mutating func write(_ value: UInt32) {
        data.append(contentsOf: [UInt8(value >> 24), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)])
    }

    mutating func writeString(_ bytes: Data) {
        write(UInt32(bytes.count))
        data.append(bytes)
    }

    mutating func writeString(_ text: String) {
        writeString(Data(text.utf8))
    }

    /// Writes an unsigned magnitude as an mpint.
    mutating func writeMPInt(_ magnitude: Data) {
        var bytes = Data(magnitude.drop { $0 == 0 })
        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }
        writeString(bytes)
    }
}
