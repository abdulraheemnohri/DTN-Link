package link.dtn.shell

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlin.concurrent.thread

/**
 * Minimal but fully functional DTN-Link chat activity. It embeds the
 * real dtn-app engine through libdtn_ffi (one node per install) and
 * drives: contact registration, sending (alias or raw EID), polling of
 * delivered bundles, conversation list with unread counts, and history.
 */
class MainActivity : Activity() {
    private lateinit var app: DtnFfi
    private lateinit var status: TextView
    private lateinit var log: TextView
    private lateinit var aliasInput: EditText
    private var openConversation: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val padded = { dp: Int -> (dp * resources.displayMetrics.density).toInt() }

        fun field(hint: String) = EditText(this).apply {
            this.hint = hint
            setSingleLine(true)
            setPadding(padded(12), padded(8), padded(12), padded(8))
        }

        aliasInput = field("contact alias")
        val eidInput = field("eid (dtn://name / ipn:n.s / bare name)")
        val peerInput = field("send to (alias or EID)")
        val bodyInput = field("message body")
        status = TextView(this).apply { setPadding(padded(12), padded(4), padded(12), padded(4)) }
        log = TextView(this).apply {
            setTextIsSelectable(true)
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = 12f
        }

        fun button(label: String, action: () -> Unit) =
            Button(this).apply { text = label; setOnClickListener { runSafely(action) } }

        val controls = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padded(8), padded(8), padded(8), padded(8))
            addView(status)
            addView(fieldHeaders())
            addView(aliasInput)
            addView(eidInput)
            addView(button("add / update contact") {
                app.addContact(aliasInput.text.toString().trim(), eidInput.text.toString().trim())
                status.text = "contact stored: ${aliasInput.text}"
            })
            addView(peerInput)
            addView(bodyInput)
            addView(button("send") {
                val row = app.send(peerInput.text.toString().trim(), bodyInput.text.toString())
                status.text = "queued (row $row); carried out on the next contact"
            })
            addView(
                LinearLayout(this@MainActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    addView(button("poll")) {
                        val msgs = app.poll()
                        render()
                        status.text = "poll: ${msgs.size} new message(s), unread ${app.unreadTotal()}"
                    }
                    addView(button("conversations")) {
                        openConversation = null
                        render()
                    }
                    addView(button("history")) {
                        openConversation = resolvePeer()
                        render()
                    }
                },
            )
        }

        val root = ScrollView(this).apply {
            setBackgroundColor(Color.WHITE)
            addView(
                LinearLayout(this@MainActivity).apply {
                    orientation = LinearLayout.VERTICAL
                    addView(controls)
                    addView(
                        TextView(this@MainActivity).apply {
                            text = "conversations / messages"
                            setPadding(padded(12), padded(12), padded(12), padded(4))
                        },
                    )
                    addView(log)
                },
            )
        }
        setContentView(root)

        thread {
            try {
                // One DTN-Link node per install; a fixed node number keeps
                // the identity stable across restarts (like an init'ed CLI
                // node). Open must run off the UI thread: SQLite plus
                // Ed25519 key generation happen on first launch.
                app = DtnFfi.open(
                    nodeNumber = 1,
                    dbPath = getDatabasePath("node.db").absolutePath,
                    strategy = Native.STRATEGY_EPIDEMIC,
                )
                // Offline catch-up poll of bundles delivered while closed.
                app.poll()
                runOnUiThread {
                    status.text = "node EID: ${app.eid}"
                    render()
                }
            } catch (e: Exception) {
                runOnUiThread { status.text = "startup failed: ${e.message}" }
            }
        }
    }

    private fun fieldHeaders() = TextView(this).apply {
        text = "CONTACTS"
        gravity = Gravity.START
    }

    /** peer = the send field as typed; aliases are resolved to their EID. */
    private fun resolvePeer(): String {
        val raw = peerInput.text.toString().trim()
        return app.resolveContact(raw) ?: raw
    }

    private fun ready() = this::app.isInitialized

    private fun render() {
        val sb = StringBuilder()
        if (!ready()) {
            log.text = "starting..."
            return
        }
        try {
            if (openConversation == null) {
                for (c in app.conversations()) {
                    sb.append(if (c.unread > 0) "(*) " else "    ")
                        .append(c.peer)
                        .append("  (+${c.unread}/${c.total})  ")
                        .append(c.lastBody.replace('\n', ' '))
                        .append('\n')
                }
                if (sb.isEmpty()) sb.append("(no conversations yet — send a message)\n")
            } else {
                for (m in app.history(openConversation!!)) {
                    sb.append(if (m.direction == Messages.DIR_IN) "[them] " else "[you]  ")
                        .append(m.body)
                        .append('\n')
                }
                openConversation?.let { app.markRead(it) }
            }
        } catch (e: Exception) {
            sb.append("error: ${e.message}\n")
        }
        log.text = sb.toString()
    }

    private fun runSafely(action: () -> Unit) {
        if (!ready()) {
            status.text = "node is still starting"
            return
        }
        try {
            action()
        } catch (e: Exception) {
            status.text = "failed: ${e.message}"
        }
    }

    override fun onDestroy() {
        if (this::app.isInitialized) app.close()
        super.onDestroy()
    }
}
