// ChatController.swift — observable chat state over the FFI bridge,
// the object the SwiftUI example renders (and an embeddable API in its
// own right for any iOS front end).
//
// NOTE on sending to peers: pollInbox/history/markRead keep the store
// open, so they must be called from a single actor context; send and
// contact management etc follow the same serialized via MainActor.
import Foundation

/// Resolves a recipient that may be an alias ("alice"), a contact EID
/// ("dtn://alice"), "dtn:none", "ipn:n.s" or a bare name.
public enum RecipientResolution {
    case alias(String)
    case raw(String)
}

@MainActor
public final class ChatController: ObservableObject {
    @Published public private(set) var conversations: [Conversation] = []
    @Published public private(set) var history: [Message] = []
    @Published public private(set) var selectedPeer: String?
    @Published public private(set) var unreadTotal: Int = 0
    @Published public private(set) var statusText: String = ""
    @Published public private(set) var eid: String = ""

    private let ffi: DtnFfi

    public init(ffi: DtnFfi) throws {
        self.ffi = ffi
        self.eid = try ffi.eid()
        // Offline catch-up at startup.
        _ = try ffi.pollInbox()
        try reload()
    }

    public func reload() throws {
        let convos = try ffi.conversations()
        let unread = try ffi.unreadTotal()
        conversations = convos
        unreadTotal = Int(unread)
        if let peer = selectedPeer {
            history = try ffi.history(peer: peer)
        }
    }

    public func select(peer: String) throws {
        selectedPeer = peer
        history = try ffi.history(peer: peer)
    }

    @discardableResult
    public func markRead(peer: String) throws -> Int {
        let changed = try ffi.markRead(peer: peer)
        try reload()
        return Int(changed)
    }

    @discardableResult
    public func addContact(alias: String, eid: String) throws -> Bool {
        let created = try ffi.addContact(alias: alias, eid: eid)
        statusText = created ? "contact \(alias) created" : "contact \(alias) updated"
        return created
    }

    public func resolve(_ text: String) -> RecipientResolution {
        if text.contains("://") || text == "dtn:none" {
            return .raw(text)
        }
        return .alias(text)
    }

    @discardableResult
    public func send(to recipient: String, body: String) throws -> Int64 {
        let peerURI: String
        switch resolve(recipient) {
        case .alias(let alias):
            guard let uri = try ffi.resolveContact(alias: alias) else {
                statusText = "unknown contact: \(alias)"
                return -1
            }
            peerURI = uri
        case .raw(let uri):
            peerURI = uri
        }
        let id = try ffi.send(peerURI: peerURI, body: body)
        try reload()
        if let peer = selectedPeer { select(peer: peer) }
        return id
    }

    /// Poll delivered bundles and refresh the UI. Returns the new message count.
    @discardableResult
    public func poll() throws -> Int {
        let messages = try ffi.pollInbox()
        try reload()
        statusText = messages.isEmpty ? "no new messages"
                                      : "\(messages.count) new message(s)"
        return messages.count
    }
}
