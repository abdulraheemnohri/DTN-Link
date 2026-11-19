// Models.swift — typed models for the flat JSON arrays dtn-ffi emits.
// Malformed input fails closed: decoding throws, never guesses.
import Foundation

public enum MessageDirection: String, Codable, Equatable {
    case inbound = "in"
    case outbound = "out"
}

public struct Message: Equatable {
    public let id: Int64
    public let peer: String
    public let direction: MessageDirection
    public let body: String
    public let createdAt: Int64
    /// Identity key of the bundle that carried the message, or nil.
    public let bundleKey: String?

    public static func parse(_ json: String, source: String = "message") throws -> [Message] {
        guard let data = json.data(using: .utf8) else {
            throw DtnJsonError.invalidUTF8(source: source)
        }
        do {
            return try JSONDecoder().decode([MessageJSON].self, from: data)
                .map(\.value)
        } catch {
            throw DtnJsonError.malformed(source: source, underlying: error)
        }
    }
}

public struct Conversation: Equatable {
    public let peer: String
    public let lastBody: String
    public let lastAt: Int64
    public let unread: Int
    public let total: Int

    public static func parse(_ json: String, source: String = "conversations") throws -> [Conversation] {
        guard let data = json.data(using: .utf8) else {
            throw DtnJsonError.invalidUTF8(source: source)
        }
        do {
            return try JSONDecoder().decode([ConversationJSON].self, from: data)
                .map(\.value)
        } catch {
            throw DtnJsonError.malformed(source: source, underlying: error)
        }
    }
}

public enum DtnJsonError: Error, CustomStringConvertible {
    case invalidUTF8(source: String)
    case malformed(source: String, underlying: Error)

    public var description: String {
        switch self {
        case .invalidUTF8(let source):
            return "dtn-ffi \(source): response is not UTF-8"
        case .malformed(let source, let under):
            return "dtn-ffi \(source): malformed JSON (\(under))"
        }
    }
}

// Decoding mirrors — exact wire shape of the FFI JSON.
struct MessageJSON: Decodable {
    let id: Int64
    let peer: String
    let direction: MessageDirection
    let body: String
    let created_at: Int64
    let bundle_key: String?

    var value: Message {
        Message(id: id, peer: peer, direction: direction, body: body,
                createdAt: created_at, bundleKey: bundle_key)
    }
}

struct ConversationJSON: Decodable {
    let peer: String
    let last_body: String
    let last_at: Int64
    let unread: Int
    let total: Int

    var value: Conversation {
        Conversation(peer: peer, lastBody: last_body, lastAt: last_at,
                     unread: unread, total: total)
    }
}
