import Foundation

/// Decoding for Bitwarden's API, which mixes casing (`access_token`, `Key`,
/// `kdfIterations`) and writes .NET dates with up to seven fractional digits.
enum BitwardenJSON {
    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .custom { path in
            CamelCaseKey(path.last!.stringValue)
        }
        decoder.dateDecodingStrategy = .custom { decoder in
            let string = try decoder.singleValueContainer().decode(String.self)
            guard let date = parseDate(string) else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Unreadable date \(string)"))
            }
            return date
        }
        return decoder
    }

    static func parseDate(_ string: String) -> Date? {
        var base = Substring(string)
        var fraction = 0.0
        if let dot = string.firstIndex(of: ".") {
            let end = string[dot...].dropFirst().firstIndex { !$0.isNumber } ?? string.endIndex
            fraction = Double("0" + string[dot..<end]) ?? 0
            base = string[..<dot] + string[end...]
        }
        if !base.hasSuffix("Z"), !base.contains("+"), base.filter({ $0 == "-" }).count < 3 {
            base += "Z"
        }
        guard let date = try? Date(String(base), strategy: .iso8601) else { return nil }
        return date.addingTimeInterval(fraction)
    }

    /// Lowercases the first letter, so PascalCase and camelCase keys both
    /// match camelCase properties.
    private struct CamelCaseKey: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }

        init(_ key: String) {
            stringValue = key.prefix(1).lowercased() + key.dropFirst()
        }

        init?(stringValue: String) {
            self.init(stringValue)
        }

        init?(intValue: Int) {
            nil
        }
    }
}
