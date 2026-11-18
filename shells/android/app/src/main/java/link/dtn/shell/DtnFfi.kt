package link.dtn.shell

/** Failure of an FFI call, carrying the native last-error message. */
class DtnFfiException(message: String) : IllegalStateException(message)

/**
 * Safe, disposable handle over the dtn-app engine embedded in the app.
 * Thread-safe: the underlying C ABI handle serializes access.
 */
class DtnFfi private constructor(private val handle: Long) : AutoCloseable {
    private var closed = false

    companion object {
        private const val DEFAULT_LIFETIME_SECONDS = 3600L

        /** Open (or create) a node + app database; throws on failure. */
        fun open(
            nodeNumber: Long,
            dbPath: String,
            strategy: Int = Native.STRATEGY_EPIDEMIC,
        ): DtnFfi {
            val h = Native.open(nodeNumber, dbPath, strategy)
            if (h == 0L) {
                throw DtnFfiException(Native.lastError() ?: "dtn_app_open failed")
            }
            return DtnFfi(h)
        }
    }

    private fun requireOpen() {
        check(!closed) { "DtnFfi handle already closed" }
    }

    /** The local node's EID URI ("dtn://..."). */
    val eid: String
        get() {
            requireOpen()
            return Native.eid(handle)
                ?: throw DtnFfiException(Native.lastError() ?: "dtn_app_eid failed")
        }

    /**
     * Compose a text message to a peer (an alias resolved through the
     * contact table, or a raw dtn:// / ipn: / dtn:none / bare-name EID).
     * Returns the stored message row id.
     */
    fun send(peer: String, body: String, lifetimeSeconds: Long = DEFAULT_LIFETIME_SECONDS): Long {
        requireOpen()
        val id = Native.send(handle, peer, body, lifetimeSeconds)
        if (id < 0) throw DtnFfiException(Native.lastError() ?: "dtn_app_send failed")
        return id
    }

    /** Drain delivered bundles into conversations; new messages this poll. */
    fun poll(): List<DtnMessage> {
        requireOpen()
        val json = Native.pollInbox(handle)
            ?: throw DtnFfiException(Native.lastError() ?: "dtn_app_poll_inbox failed")
        return Messages.parseMessages(json)
    }

    /** All conversations, most recently active first. */
    fun conversations(): List<Conversation> {
        requireOpen()
        val json = Native.conversations(handle)
            ?: throw DtnFfiException(Native.lastError() ?: "dtn_app_conversations failed")
        return Messages.parseConversations(json)
    }

    /** Full history of one peer's conversation, oldest first. */
    fun history(peer: String): List<DtnMessage> {
        requireOpen()
        val json = Native.history(handle, peer)
            ?: throw DtnFfiException(Native.lastError() ?: "dtn_app_history failed")
        return Messages.parseMessages(json)
    }

    /** Total unread inbound messages across all conversations. */
    fun unreadTotal(): Int {
        requireOpen()
        val n = Native.unreadTotal(handle)
        if (n < 0) throw DtnFfiException(Native.lastError() ?: "dtn_app_unread_total failed")
        return n.toInt()
    }

    /** Mark every inbound message of [peer] read; returns messages changed. */
    fun markRead(peer: String): Int {
        requireOpen()
        val n = Native.markRead(handle, peer)
        if (n < 0) throw DtnFfiException(Native.lastError() ?: "dtn_app_mark_read failed")
        return n.toInt()
    }

    /** Register (or re-point) an alias; true when newly created. */
    fun addContact(alias: String, eid: String): Boolean {
        requireOpen()
        return when (Native.addContact(handle, alias, eid)) {
            1 -> true
            0 -> false
            else -> throw DtnFfiException(Native.lastError() ?: "dtn_app_add_contact failed")
        }
    }

    /** Resolve an alias to its EID URI, or null when unknown. */
    fun resolveContact(alias: String): String? {
        requireOpen()
        return Native.resolveContact(handle, alias)
    }

    override fun close() {
        if (!closed) {
            closed = true
            Native.close(handle)
        }
    }
}
