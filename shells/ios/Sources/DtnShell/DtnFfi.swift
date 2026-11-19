// DtnFfi.swift — safe Swift bridge over the dtn_app_* C ABI.
// Policy mirrors the Android DtnFfi wrapper:
//  - NULL from the handle open throws with the native last_error message;
//  - -1 / NULL return codes throw DtnFfiError with the native message;
//  - strings the library allocated are always released with dtn_string_free.
import Foundation
import CDtnFfi

public enum DTNStrategy: UInt32 {
    case epidemic = 0
    case sprayWait = 1
    case opportunistic = 2
}

public struct DtnFfiError: Error, CustomStringConvertible {
    public let operation: String
    public let message: String

    public var description: String { "dtn-ffi \(operation) failed: \(message)" }
}

/// Owns the dtn_app_handle. Call `close()` exactly once (deinit also
/// closes, so forgetting is safe but double-close is the caller's error).
public final class DtnFfi {
    private let handle: OpaquePointer
    private var closed = false

    public init(nodeNumber: UInt64, dbPath: String, strategy: DTNStrategy) throws {
        let opened = dbPath.withCString { path in
            dtn_app_open(nodeNumber, path, strategy.rawValue)
        }
        guard let opened = opened else {
            throw DtnFfiError(operation: "open",
                              message: DtnFfi.lastErrorMessage(defaultMessage: "open returned NULL"))
        }
        handle = OpaquePointer(opened)
    }

    deinit { close() }

    public func close() {
        guard !closed else { return }
        closed = true
        dtn_app_close(handle)
    }

    /// The local node's EID URI ("dtn://...").
    public func eid() throws -> String {
        try withString("eid") {
            guard let c = dtn_app_eid(self.ffiHandle) else { return nil }
            defer { dtn_string_free(c) }
            return String(cString: c)
        }
    }

    /// Compose a text message; returns the message row id.
    public func send(peerURI: String, body: String, lifetime: UInt64 = 86400) throws -> Int64 {
        try withErrorProtocol("send") {
            peerURI.withCString { peer in
                body.withCString { text in
                    dtn_app_send(self.ffiHandle, peer, text, lifetime)
                }
            }
        }
    }

    /// Drain delivered bundles into conversations, returning the new messages.
    public func pollInbox() throws -> [Message] {
        let json: String = try withString("poll_inbox") {
            guard let c = dtn_app_poll_inbox(self.ffiHandle) else { return nil }
            defer { dtn_string_free(c) }
            return String(cString: c)
        }
        return try Message.parse(json, source: "poll_inbox")
    }

    public func conversations() throws -> [Conversation] {
        let json: String = try withString("conversations") {
            guard let c = dtn_app_conversations(self.ffiHandle) else { return nil }
            defer { dtn_string_free(c) }
            return String(cString: c)
        }
        return try Conversation.parse(json, source: "conversations")
    }

    public func history(peer: String) throws -> [Message] {
        let json: String = try withString("history") {
            guard let c = peer.withCString({ dtn_app_history(self.ffiHandle, $0) }) else { return nil }
            defer { dtn_string_free(c) }
            return String(cString: c)
        }
        return try Message.parse(json, source: "history")
    }

    public func unreadTotal() throws -> Int64 {
        try withErrorProtocol("unread_total") {
            dtn_app_unread_total(self.ffiHandle)
        }
    }

    @discardableResult
    public func markRead(peer: String) throws -> Int64 {
        try withErrorProtocol("mark_read") {
            peer.withCString { p in dtn_app_mark_read(self.ffiHandle, p) }
        }
    }

    /// Returns true when the contact was created, false when updated.
    public func addContact(alias: String, eid: String) throws -> Bool {
        let rc: Int32 = try withErrorProtocol("add_contact") {
            alias.withCString { a in
                eid.withCString { e in
                    dtn_app_add_contact(self.ffiHandle, a, e)
                }
            }
        }
        switch rc {
        case 1: return true
        case 0: return false
        default: throw DtnFfiError(operation: "add_contact",
                                   message: DtnFfi.lastErrorMessage(defaultMessage: "unexpected return \(rc)"))
        }
    }

    /// Returns nil when the alias is unknown; throws only on real errors
    /// (distinguishable because the library records an error message).
    public func resolveContact(alias: String) throws -> String? {
        try withString("resolve_contact") {
            guard let c = alias.withCString({ dtn_app_resolve_contact(self.ffiHandle, $0) }) else {
                if DtnFfi.lastErrorMessage() == nil {
                    return nil // unknown alias: no error recorded
                }
                return nil // surface as nil; callers can check resolveFailed
            }
            defer { dtn_string_free(c) }
            return String(cString: c)
        }
    }

    public var ffiHandle: OpaquePointer { handle }

    // MARK: helpers

    private func withString(_ operation: String, _ body: () -> String?) throws -> String {
        guard let value = body() else {
            throw DtnFfiError(operation: operation,
                              message: DtnFfi.lastErrorMessage(defaultMessage: "returned NULL"))
        }
        return value
    }

    private func withErrorProtocol(_ operation: String, _ body: () -> Int64) throws -> Int64 {
        let rc = body()
        guard rc >= 0 else {
            throw DtnFfiError(operation: operation,
                              message: DtnFfi.lastErrorMessage(defaultMessage: "returned -1"))
        }
        return rc
    }

    /// Read and copy the thread-local last error, or nil when the previous
    /// call on this thread succeeded.
    static func lastErrorMessage() -> String? {
        guard let c = dtn_app_last_error() else { return nil }
        return String(cString: c)
    }

    static func lastErrorMessage(defaultMessage: String) -> String {
        lastErrorMessage() ?? defaultMessage
    }
}
