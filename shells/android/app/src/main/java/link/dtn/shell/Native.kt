package link.dtn.shell

/**
 * The direct JNI surface of libdtn_ffi (built with cargo feature `jni`).
 *
 * Every `external fun` maps 1:1 to an exported
 * Java_link_dtn_shell_Native_* symbol in crates/dtn-ffi/src/jni_shim.rs,
 * which in turn calls the exact `dtn_app_*` C ABI from dtn_app_ffi.h.
 *
 * Null-return semantics follow the C ABI: null means failure (or "not
 * found" for resolve), and the reason is the thread-local FFI last
 * error readable via [lastError]. Strings returned by the library are
 * released inside the shim with `dtn_string_free`.
 */
object Native {
    init {
        // Built per ABI with (line continuations shown with backslash):
        //   cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64
        //       -o shells/android/app/src/main/jniLibs build --release
        //       -p dtn-ffi --features jni
        System.loadLibrary("dtn_ffi")
    }

    // Routing strategy codes — must match dtn_app_ffi.h.
    const val STRATEGY_EPIDEMIC = 0
    const val STRATEGY_SPRAY_WAIT = 1
    const val STRATEGY_OPPORTUNISTIC = 2

    // Lifecycle.
    external fun open(nodeNumber: Long, dbPath: String, strategy: Int): Long
    external fun close(handle: Long)

    // Identity + messaging.
    external fun eid(handle: Long): String?
    external fun send(handle: Long, peer: String, body: String, lifetime: Long): Long
    external fun pollInbox(handle: Long): String?
    external fun conversations(handle: Long): String?
    external fun history(handle: Long, peer: String): String?
    external fun unreadTotal(handle: Long): Long
    external fun markRead(handle: Long, peer: String): Long

    // Contacts.
    external fun addContact(handle: Long, alias: String, eid: String): Int
    external fun resolveContact(handle: Long, alias: String): String?

    // Error protocol (library-owned string, never freed here).
    external fun lastError(): String?
}
