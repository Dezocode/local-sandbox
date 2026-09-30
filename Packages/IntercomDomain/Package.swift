// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "IntercomDomain",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "IntercomDomain", targets: ["IntercomDomain"]),
        // Additive only; does not replace the required XCTest suite.
        .executable(name: "IntercomDomainContracts", targets: ["IntercomDomainContracts"])
    ],
    targets: [
        .target(name: "IntercomDomain"),
        .testTarget(
            name: "IntercomDomainTests",
            dependencies: ["IntercomDomain"]
        ),
        .executableTarget(
            name: "IntercomDomainContracts",
            dependencies: ["IntercomDomain"],
            path: "Tests/IntercomDomainContracts"
        )
    ]
)
