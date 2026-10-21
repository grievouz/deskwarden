// swift-tools-version: 6.0
import Foundation
import PackageDescription

// The Bitwarden SDK is built locally by scripts/build-bitwarden-sdk.sh. Without
// it, only the socket library, harness and their tests are available, so the
// varlock plugin's tests don't need the Rust build.
let sdkPath = "Vendor/BitwardenSdk"
let hasSDK = FileManager.default.fileExists(
    atPath: URL(fileURLWithPath: Context.packageDirectory).appendingPathComponent("\(sdkPath)/Package.swift").path
)

var products: [Product] = []
var dependencies: [Package.Dependency] = []
var targets: [Target] = [
    .target(
        name: "DeskwardenKit",
        linkerSettings: [
            .linkedFramework("LocalAuthentication"),
            .linkedFramework("Network"),
            .linkedFramework("Security"),
        ]
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

if hasSDK {
    products.append(.executable(name: "Deskwarden", targets: ["Deskwarden"]))
    dependencies.append(.package(path: sdkPath))
    targets += [
        // Bitwarden sign-in, sync and the unlocked vault. The only code that links the SDK.
        .target(
            name: "DeskwardenAccount",
            dependencies: [
                "DeskwardenKit",
                .product(name: "BitwardenSdk", package: "BitwardenSdk"),
            ]
        ),
        .executableTarget(
            name: "Deskwarden",
            dependencies: ["DeskwardenKit", "DeskwardenAccount"]
        ),
        .testTarget(
            name: "DeskwardenAccountTests",
            dependencies: ["DeskwardenAccount"]
        ),
    ]
}

let package = Package(
    name: "Deskwarden",
    platforms: [.macOS(.v15)],
    products: products,
    dependencies: dependencies,
    targets: targets
)
