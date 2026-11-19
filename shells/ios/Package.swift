// swift-tools-version:5.7
// DTN-Link iOS shell — Phase 22.
// DtnModels testable without the native library; DtnShell bridges libdtn_ffi.
import PackageDescription

let package = Package(
    name: "DtnShell",
    products: [
        .library(name: "DtnModels", targets: ["DtnModels"]),
        .library(name: "DtnShell", targets: ["DtnShell"]),
    ],
    targets: [
        .target(
            name: "CDtnFfi",
            path: "Sources/CDtnFfi",
            cSettings: [
                .headerSearchPath("include")
            ]
        ),
        .target(
            name: "DtnModels",
            dependencies: [],
            path: "Sources/DtnModels"
        ),
        .target(
            name: "DtnShell",
            dependencies: ["CDtnFfi", "DtnModels"],
            path: "Sources/DtnShell",
            linkerSettings: [
                .linkedLibrary("dtn_ffi")
            ]
        ),
        .testTarget(
            name: "DtnShellTests",
            dependencies: ["DtnModels"],
            path: "Tests/DtnShellTests"
        ),
    ]
)
