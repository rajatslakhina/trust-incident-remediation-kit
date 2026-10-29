// swift-tools-version:6.0
import PackageDescription

// Platforms declared here are exactly the ones CI builds:
// iOS (xcodebuild, generic iOS Simulator) and macOS (swift build/test on macos-15).
// Linux is built and tested by CI too; it needs no platform entry.
let package = Package(
    name: "TrustRemediation",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "TrustRemediation", targets: ["TrustRemediation"]),
        .library(name: "TrustRemediationUI", targets: ["TrustRemediationUI"]),
    ],
    dependencies: [
        // Build-vs-buy: Ed25519 is not something to hand-roll. swift-crypto re-exports
        // CryptoKit on Apple platforms and uses BoringSSL on Linux, so the exact same
        // verification code is exercised by the Linux test job.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"4.0.0"),
    ],
    targets: [
        .target(
            name: "TrustRemediation",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]
        ),
        .target(
            name: "TrustRemediationUI",
            dependencies: ["TrustRemediation"]
        ),
        .testTarget(
            name: "TrustRemediationTests",
            dependencies: [
                "TrustRemediation",
                "TrustRemediationUI",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
    ]
)
