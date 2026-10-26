// swift-tools-version:5.9
//
// Parabellum menu bar app (SwiftUI) + ParabellumKit (Foundation-only IPC client and models).
// Build: `swift build -c release --arch arm64` → `.build/arm64-apple-macosx/release/Parabellum`.
import PackageDescription

let package = Package(
    name: "Parabellum",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "Parabellum", targets: ["Parabellum"]),
        .library(name: "ParabellumKit", targets: ["ParabellumKit"]),
    ],
    targets: [
        .target(
            name: "ParabellumKit",
            path: "Sources/ParabellumKit"
        ),
        .executableTarget(
            name: "Parabellum",
            dependencies: ["ParabellumKit"],
            path: "Sources/Parabellum"
        ),
        .testTarget(
            name: "ParabellumKitTests",
            dependencies: ["ParabellumKit"],
            path: "Tests/ParabellumKitTests",
            resources: [.copy("Fixtures")]
        ),
    ],
    swiftLanguageVersions: [.v5]
)
