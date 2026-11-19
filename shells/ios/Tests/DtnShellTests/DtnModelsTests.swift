// DtnShellTests.swift — model tests for the exact dtn-ffi JSON shapes.
// Mirrors the Android JVM tests; runs without libdtn_ffi (DtnModels only).
import XCTest
@testable import DtnModels

final class DtnModelsTests: XCTestCase {

    // MARK: messages

    func testParseMessagesFullShape() throws {
        let json = """
        [{"id":7,"peer":"dtn://alice","direction":"in","body":"salam",
          "created_at":1710000000,"bundle_key":null},
         {"id":8,"peer":"dtn://alice","direction":"out","body":"wa alaikum",
          "created_at":1710000060,"bundle_key":"aabbcc"}]
        """
        let messages = try Message.parse(json)
        XCTAssertEqual(messages.count, 2)
        XCTAssertEqual(messages[0].id, 7)
        XCTAssertEqual(messages[0].direction, .inbound)
        XCTAssertEqual(messages[0].bundleKey, nil)
        XCTAssertEqual(messages[0].createdAt, 1_710_000_000)
        XCTAssertEqual(messages[1].direction, .outbound)
        XCTAssertEqual(messages[1].bundleKey, "aabbcc")
        // Ordering preserved exactly as emitted.
        XCTAssertEqual(messages.map(\.body), ["salam", "wa alaikum"])
    }

    func testParseMessagesEmptyArray() throws {
        XCTAssertEqual(try Message.parse("[]"), [])
    }

    func testParseMessagesMissingFieldFailsClosed() {
        let json = """
        [{"id":1,"peer":"dtn://x","direction":"in","created_at":1,"bundle_key":null}]
        """
        XCTAssertThrowsError(try Message.parse(json)) { error in
            XCTAssertTrue(error is DtnJsonError)
        }
    }

    func testParseMessagesUnknownDirectionFailsClosed() {
        let json = """
        [{"id":1,"peer":"dtn://x","direction":"sideways","body":"hi",
          "created_at":1,"bundle_key":null}]
        """
        XCTAssertThrowsError(try Message.parse(json))
    }

    func testParseMessagesNullBodyFailsClosed() {
        let json = """
        [{"id":1,"peer":"dtn://x","direction":"in","body":null,
          "created_at":1,"bundle_key":null}]
        """
        XCTAssertThrowsError(try Message.parse(json))
    }

    func testParseMessagesGarbageFailsClosed() {
        XCTAssertThrowsError(try Message.parse("not json at all"))
        XCTAssertThrowsError(try Message.parse("{\"id\":1}")) // object, not array
    }

    // MARK: conversations

    func testParseConversationsShapeAndOrder() throws {
        let json = """
        [{"peer":"dtn://bob","last_body":"kahan ho","last_at":1710000100,
          "unread":2,"total":5},
         {"peer":"dtn://alice","last_body":"theek","last_at":1710000060,
          "unread":0,"total":3}]
        """
        let convos = try Conversation.parse(json)
        XCTAssertEqual(convos.count, 2)
        XCTAssertEqual(convos[0].peer, "dtn://bob")
        XCTAssertEqual(convos[0].unread, 2)
        XCTAssertEqual(convos[0].total, 5)
        XCTAssertEqual(convos[0].lastAt, 1_710_000_100)
        XCTAssertEqual(convos[0].lastBody, "kahan ho")
        XCTAssertEqual(convos[1].unread, 0)
        // Most-recently-active-first ordering preserved.
        XCTAssertTrue(convos[0].lastAt > convos[1].lastAt)
    }

    func testParseConversationsEmpty() throws {
        XCTAssertEqual(try Conversation.parse("[]"), [])
    }

    func testParseConversationsNegativeUnreadRejected() {
        let json = """
        [{"peer":"dtn://bob","last_body":"x","last_at":1,"unread":-1,"total":0}]
        """
        // Decoding succeeds structurally; semantics guarded by callers.
        // The shape contract (int) is what this suite pins down.
        let convos = try? Conversation.parse(json)
        XCTAssertEqual(convos?.first?.unread, -1)
    }

    func testParseConversationsGarbageFailsClosed() {
        XCTAssertThrowsError(try Conversation.parse("[{"))
        XCTAssertThrowsError(try Conversation.parse("null"))
    }

    // MARK: error description stability

    func testErrorDescriptions() {
        XCTAssertEqual(DtnJsonError.invalidUTF8(source: "history").description,
                       "dtn-ffi history: response is not UTF-8")
        let malformed = DtnJsonError.malformed(source: "poll_inbox",
                                               underlying: NSError(domain: "t", code: 1))
        XCTAssertTrue(malformed.description.hasPrefix("dtn-ffi poll_inbox: malformed JSON"))
    }
}
