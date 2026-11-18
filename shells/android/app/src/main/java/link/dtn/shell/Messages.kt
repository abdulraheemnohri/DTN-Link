package link.dtn.shell

import org.json.JSONArray

/**
 * Typed models over the flat JSON array shapes dtn-ffi emits
 * (dtn_app_poll_inbox / dtn_app_history and dtn_app_conversations).
 * These are the exact shapes documented in dtn_app_ffi.h; malformed
 * input throws org.json.JSONException instead of being guessed at.
 */

/** One chat message (direction is [Messages.DIR_IN] or [Messages.DIR_OUT]). */
data class DtnMessage(
    val id: Long,
    val peer: String,
    val direction: String,
    val body: String,
    val createdAt: Long,
    /** Identity key of the bundle that carried this message, if known. */
    val bundleKey: String?,
)

/** One conversation, most recently active first (FFI ordering). */
data class Conversation(
    val peer: String,
    val lastBody: String,
    val lastAt: Long,
    val unread: Int,
    val total: Int,
)

object Messages {
    const val DIR_IN = "in"
    const val DIR_OUT = "out"

    /** Parse a poll/history JSON array. */
    fun parseMessages(json: String): List<DtnMessage> {
        val arr = JSONArray(json)
        val out = ArrayList<DtnMessage>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out.add(
                DtnMessage(
                    id = o.getLong("id"),
                    peer = o.getString("peer"),
                    direction = o.getString("direction"),
                    body = o.getString("body"),
                    createdAt = o.getLong("created_at"),
                    bundleKey = if (o.isNull("bundle_key")) null else o.getString("bundle_key"),
                ),
            )
        }
        return out
    }

    /** Parse a conversation-list JSON array (FFI order preserved). */
    fun parseConversations(json: String): List<Conversation> {
        val arr = JSONArray(json)
        val out = ArrayList<Conversation>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out.add(
                Conversation(
                    peer = o.getString("peer"),
                    lastBody = o.getString("last_body"),
                    lastAt = o.getLong("last_at"),
                    unread = o.optInt("unread", 0),
                    total = o.optInt("total", 0),
                ),
            )
        }
        return out
    }
}
