// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "IPMITool",
    platforms: [
        .macOS(.v12),
        .iOS(.v15)
    ],
    products: [
        .library(name: "SwiftIPMI", targets: ["SwiftIPMI"]),
    ],
    targets: [
        .target(
            name: "SwiftIPMI",
            path: "Sources/SwiftIPMI"
        ),
        .testTarget(
            name: "SwiftIPMITests",
            dependencies: ["SwiftIPMI"],
            path: "Tests/SwiftIPMITests"
        )
    ],
    swiftLanguageModes: [.v6]
)
