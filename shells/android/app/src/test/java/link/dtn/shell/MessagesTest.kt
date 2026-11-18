package link.dtn.shell

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests over exactly the JSON array shapes dtn-ffi emits (the
 * same shapes the desktop shell's json.c reads); see
 * crates/dtn-ffi/src/lib.rs and dtn_app_ffi.h.
 */
class MessagesTest {
    private fun msg(
        id: Long,
        peer: String,
        dir: String,
        body: String,
        at: Long,
        key: String?,
    ): String {
        val o = JSONObject()
        o.put("id", id)
        o.put("peer", peer)
        o.put("direction", dir)
        o.put("body", body)
        o.put("created_at", at)
        o.put("bundle_key", key ?: JSONObject.NULL)
        return o.toString()
    }

    @Test
    fun parsesAPollResultIncludingNullBundleKey() {
        val json = "[" +
            msg(7, "dtn://bob", "in", "see you at the pass", 1700000000, null) +
            "]"
        val msgs = Messages.parseMessages(json)
        assertEquals(1, msgs.size)
        with(msgs[0]) {
            assertEquals(7L, id)
            assertEquals("dtn://bob", peer)
            assertEquals(Messages.DIR_IN, direction)
            assertEquals("see you at the pass", body)
            assertEquals(1700000000L, createdAt)
            assertNull(bundleKey)
        }
    }

    @Test
    fun parsesHistoryWithCarryingBundleKeyAndEscapes() {
        val json = "[" +
            msg(1, "dtn://bob", "in", "line\nbreak\t\"quoted\"", 1, "dk1") +
            "," +
            msg(2, "dtn://bob", "out", "reply", 2, null) +
            "]"
        val msgs = Messages.parseMessages(json)
        assertEquals(2, msgs.size)
        assertEquals("line\nbreak\t\"quoted\"", msgs[0].body)
        assertEquals("dk1", msgs[0].bundleKey)
        assertEquals(Messages.DIR_OUT, msgs[1].direction)
        // FFI order (oldest first for history) is preserved.
        assertEquals(1L, msgs.first().id)
        assertEquals(2L, msgs.last().id)
    }

    @Test
    fun parsesConversationListWithCounts() {
        val json = "[" +
            "{\"peer\":\"dtn://alice\",\"last_body\":\"hi\",\"last_at\":42," +
            "\"unread\":3,\"total\":10}," +
            "{\"peer\":\"dtn://bob\",\"last_body\":\"yo\",\"last_at\":7," +
            "\"unread\":0,\"total\":2}" +
            "]"
        val convs = Messages.parseConversations(json)
        assertEquals(2, convs.size)
        with(convs[0]) {
            assertEquals("dtn://alice", peer)
            assertEquals("hi", lastBody)
            assertEquals(42L, lastAt)
            assertEquals(3, unread)
            assertEquals(10, total)
        }
        // Most-recently-active-first ordering is FFI output; kept as is.
        assertTrue(convs[0].lastAt > convs[1].lastAt)
    }

    @Test
    fun emptyArraysParseToEmptyLists() {
        assertTrue(Messages.parseMessages("[]").isEmpty())
        assertTrue(Messages.parseConversations("[]").isEmpty())
    }

    @Test
    fun malformedJSONFailsClosed() {
        val badInputs = listOf(
            "",
            "not json",
            "{\"not\":\"an array\"}",
            "[{\"id\":\"x\",\"peer\":\"p\",\"direction\":\"in\",\"body\":\"b\"," +
                "\"created_at\":1,\"bundle_key\":null}]",
        )
        for (bad in badInputs) {
            try {
                Messages.parseMessages(bad)
                org.junit.Assert.fail("expected a JSONException for: $bad")
            } catch (expected: org.json.JSONException) {
                // fail closed, like the desktop shell's json.c reader
            }
        }
    }
}
