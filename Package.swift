// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Deskwarden",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "Deskwarden", targets: ["Deskwarden"]),
    ],
    targets: [
        .target(
            name: "DeskwardenKit",
            linkerSettings: [
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Network"),
                .linkedFramework("Security"),
            ]
        ),
        .executableTarget(
            name: "Deskwarden",
            dependencies: ["DeskwardenKit"]
        ),
        // Runs the secrets socket against fixture items, for the varlock plugin's e2e tests.
        .executableTarget(
            name: "SocketHarness",
            dependencies: ["DeskwardenKit"]
        ),
        .testTarget(
            name: "DeskwardenKitTests",
            dependencies: ["DeskwardenKit"]
        ),
    ]
)
