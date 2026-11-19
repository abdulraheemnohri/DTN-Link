// ShellApp.swift — Phase 22 example iOS app entry point.
// A minimal but functional DTN-Link chat front end driving DtnFfi.
import SwiftUI
import DtnShell

@main
struct DtnShellApp: App {
    @StateObject private var controller: ChatController

    init() {
        let nodeNumber = UInt64(ProcessInfo.processInfo
            .environment["DTN_NODE_NUMBER"].flatMap { UInt64($0) } ?? 1)
        let dbPath = DtnShellApp.databaseDirectory()
            .appendingPathComponent("node-\(nodeNumber).db").path
        do {
            let ffi = try DtnFfi(nodeNumber: nodeNumber,
                                 dbPath: dbPath,
                                 strategy: .epidemic)
            _controller = StateObject(wrappedValue: try ChatController(ffi:))
        } catch {
            fatalError("DTN-Link failed to open the node: \(error)")
        }
    }

    var body: some Scene {
        WindowGroup {
            ChatView()
                .environmentObject(controller)
        }
    }

    /// Application-support directory for the SQLite node database.
    static func databaseDirectory() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory,
                                            in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("DTNLink", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir,
                                                 withIntermediateDirectories: true)
        return dir
    }
}
