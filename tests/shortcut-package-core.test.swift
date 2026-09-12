import Foundation

func require(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() { fatalError(message) }
}

func expect(_ expected: ShortcutPackageValidationError, _ body: () throws -> Void) {
    do {
        try body()
        fatalError("Expected \(expected)")
    } catch let actual as ShortcutPackageValidationError {
        require(actual == expected, "Expected \(expected), received \(actual)")
    } catch {
        fatalError("Unexpected error: \(error)")
    }
}

@main
enum ShortcutPackageCoreTests {
    static func main() throws {
        let bytes = Data("signed-shortcut-package".utf8)
        let digest = ShortcutPackageContract.sha256(bytes)
        let local = ShortcutPackage(
            id: "local",
            name: "Agent Step - Local",
            url: ShortcutPackageContract.canonicalPackageURL(id: "local"),
            sha256: digest,
            bytes: bytes.count,
            requires: []
        )
        let runner = ShortcutPackage(
            id: "runner",
            name: "Local Sandbox",
            url: ShortcutPackageContract.canonicalPackageURL(id: "runner"),
            sha256: digest,
            bytes: bytes.count,
            requires: ["local"]
        )
        let signed = ShortcutCatalog(
            version: 1,
            release: "0.3.0",
            status: "signed-awaiting-device-acceptance",
            packages: [runner, local]
        )
        let signedPackages = try signed.validated()
        require(signedPackages.map(\.id) == ["local", "runner"], "canonical signed catalog did not sort dependencies")
        let unavailable = ShortcutCatalog(
            version: 1,
            release: "0.3.0",
            status: "awaiting-signed-device-exports",
            packages: []
        )
        let unavailablePackages = try unavailable.validated()
        require(unavailablePackages.isEmpty, "explicitly unavailable empty catalog was rejected")

        expect(.invalidCatalog) {
            _ = try ShortcutCatalog(version: 1, release: "0.3.1", status: ShortcutPackageContract.signedStatus, packages: [local]).validated()
        }
        expect(.signedCatalogRequired) {
            _ = try ShortcutCatalog(version: 1, release: "0.3.0", status: ShortcutPackageContract.unavailableStatus, packages: [local]).validated()
        }
        expect(.unavailableCatalogStatusRequired) {
            _ = try ShortcutCatalog(version: 1, release: "0.3.0", status: ShortcutPackageContract.signedStatus, packages: []).validated()
        }
        let wrongHost = ShortcutPackage(id: "local", name: local.name, url: URL(string: "https://example.test/shortcuts/0.3.0/local.shortcut")!, sha256: digest, bytes: bytes.count, requires: [])
        expect(.invalidPackage) {
            _ = try ShortcutCatalog(version: 1, release: "0.3.0", status: ShortcutPackageContract.signedStatus, packages: [wrongHost]).validated()
        }
        let wrongPath = ShortcutPackage(id: "local", name: local.name, url: URL(string: "\(ShortcutPackageContract.canonicalOrigin)/shortcuts/0.3.0/other.shortcut")!, sha256: digest, bytes: bytes.count, requires: [])
        expect(.invalidPackage) {
            _ = try ShortcutCatalog(version: 1, release: "0.3.0", status: ShortcutPackageContract.signedStatus, packages: [wrongPath]).validated()
        }
        let selfHostedOrigin = "https://sandbox.example.test:8443"
        let selfHosted = ShortcutPackage(
            id: local.id,
            name: local.name,
            url: ShortcutPackageContract.canonicalPackageURL(id: local.id, distributionOrigin: selfHostedOrigin),
            sha256: local.sha256,
            bytes: local.bytes,
            requires: local.requires
        )
        let selfHostedCatalog = ShortcutCatalog(
            version: 1,
            release: "0.3.0",
            status: ShortcutPackageContract.signedStatus,
            packages: [selfHosted]
        )
        let candidateSelfHostedOrigin = try selfHostedCatalog.candidateDistributionOrigin()
        let approvedSelfHostedPackages = try selfHostedCatalog.validated(distributionOrigin: selfHostedOrigin)
        require(candidateSelfHostedOrigin == selfHostedOrigin, "self-host candidate origin was not normalized exactly")
        require(approvedSelfHostedPackages == [selfHosted], "explicitly approved self-host origin was rejected")
        expect(.invalidPackage) { _ = try selfHostedCatalog.validated() }
        expect(.invalidDistributionOrigin) {
            _ = try ShortcutPackageContract.validatedDistributionOrigin("https://sandbox.example.test/custom")
        }
        expect(.invalidDistributionOrigin) {
            _ = try ShortcutPackageContract.validatedDistributionOrigin("https://user@sandbox.example.test")
        }
        expect(.invalidDistributionOrigin) {
            _ = try ShortcutPackageContract.validatedDistributionOrigin("https://sandbox.example.test:443")
        }
        let queriedPackage = ShortcutPackage(id: local.id, name: local.name, url: URL(string: selfHosted.url.absoluteString + "?replace=1")!, sha256: local.sha256, bytes: local.bytes, requires: [])
        expect(.invalidPackage) {
            _ = try ShortcutCatalog(version: 1, release: "0.3.0", status: ShortcutPackageContract.signedStatus, packages: [queriedPackage]).validated(distributionOrigin: selfHostedOrigin)
        }
        let invalidID = ShortcutPackage(id: "invalid\nid", name: local.name, url: local.url, sha256: digest, bytes: bytes.count, requires: [])
        expect(.invalidPackage) {
            _ = try ShortcutCatalog(version: 1, release: "0.3.0", status: ShortcutPackageContract.signedStatus, packages: [invalidID]).validated()
        }
        let uppercaseDigest = ShortcutPackage(id: local.id, name: local.name, url: local.url, sha256: String(repeating: "A", count: 64), bytes: bytes.count, requires: [])
        expect(.invalidPackage) {
            _ = try ShortcutCatalog(version: 1, release: "0.3.0", status: ShortcutPackageContract.signedStatus, packages: [uppercaseDigest]).validated()
        }
        let unicodeName = ShortcutPackage(id: local.id, name: "Agént Step", url: local.url, sha256: local.sha256, bytes: local.bytes, requires: [])
        expect(.invalidPackage) {
            _ = try ShortcutCatalog(version: 1, release: "0.3.0", status: ShortcutPackageContract.signedStatus, packages: [unicodeName]).validated()
        }
        let duplicateName = ShortcutPackage(id: "other", name: local.name, url: ShortcutPackageContract.canonicalPackageURL(id: "other"), sha256: local.sha256, bytes: local.bytes, requires: [])
        expect(.invalidCatalog) {
            _ = try ShortcutCatalog(version: 1, release: "0.3.0", status: ShortcutPackageContract.signedStatus, packages: [local, duplicateName]).validated()
        }

        let exactJSON = """
        {"version":1,"release":"0.3.0","status":"signed-awaiting-device-acceptance","packages":[{"id":"local","name":"Agent Step - Local","url":"\(local.url.absoluteString)","sha256":"\(digest)","bytes":\(bytes.count),"requires":[]}]}
        """.data(using: .utf8)!
        let decodedPackages = try JSONDecoder().decode(ShortcutCatalog.self, from: exactJSON).validated()
        require(decodedPackages == [local], "exact catalog JSON failed to decode")
        for changedJSON in [
            String(data: exactJSON, encoding: .utf8)!.replacingOccurrences(of: "{\"version\":", with: "{\"unexpected\":true,\"version\":"),
            String(data: exactJSON, encoding: .utf8)!.replacingOccurrences(of: "{\"id\":\"local\"", with: "{\"unexpected\":true,\"id\":\"local\""),
        ] {
            do {
                _ = try JSONDecoder().decode(ShortcutCatalog.self, from: Data(changedJSON.utf8))
                fatalError("Catalog decoder accepted an unexpected schema field")
            } catch is DecodingError {
                // Expected exact-schema rejection.
            }
        }

        let okResponse = HTTPURLResponse(url: local.url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
        try ShortcutPackageContract.validateHTTPResponse(okResponse, for: local)
        let redirectResponse = HTTPURLResponse(url: local.url, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: ["Location": runner.url.absoluteString])!
        expect(.redirectRejected) { try ShortcutPackageContract.validateHTTPResponse(redirectResponse, for: local) }
        let redirectedFinalResponse = HTTPURLResponse(url: runner.url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
        expect(.redirectRejected) { try ShortcutPackageContract.validateHTTPResponse(redirectedFinalResponse, for: local) }
        let missingResponse = HTTPURLResponse(url: local.url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: nil)!
        expect(.httpStatus(404)) { try ShortcutPackageContract.validateHTTPResponse(missingResponse, for: local) }

        try ShortcutPackageContract.verifyDownloadedData(bytes, for: local)
        expect(.sizeMismatch(expected: bytes.count, actual: bytes.count + 1)) {
            try ShortcutPackageContract.verifyDownloadedData(bytes + Data([0]), for: local)
        }
        let wrongDigest = ShortcutPackage(id: local.id, name: local.name, url: local.url, sha256: String(repeating: "0", count: 64), bytes: bytes.count, requires: [])
        expect(.digestMismatch) { try ShortcutPackageContract.verifyDownloadedData(bytes, for: wrongDigest) }

        let temporaryRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shortcut-package-core-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: temporaryRoot) }
        let verified = try ShortcutPackageContract.materializeVerifiedPackage(bytes, for: local, temporaryRoot: temporaryRoot)
        require(verified.fileURL.isFileURL && verified.fileURL.pathExtension == "shortcut", "verified package was not materialized as a local .shortcut")
        let verifiedReadback = try Data(contentsOf: verified.fileURL)
        require(verifiedReadback == bytes, "verified local package readback changed bytes")

        var gate = ShortcutPackageInstallGate()
        require(gate.begin("local"), "first package verification did not acquire the install gate")
        require(gate.isBusy && !gate.begin("runner"), "duplicate package verification acquired the install gate")
        gate.finish("runner")
        require(gate.isBusy, "a different package released the install gate")
        gate.finish("local")
        require(!gate.isBusy && gate.begin("runner"), "completed verification did not release the install gate")

        let verifiedMessage = ShortcutPackageOpenOutcome.verified(local.name).message
        let acceptedMessage = ShortcutPackageOpenOutcome.accepted(local.name).message
        let rejectedMessage = ShortcutPackageOpenOutcome.rejected(local.name).message
        require(verifiedMessage.contains("Waiting for iOS") && verifiedMessage.contains("Installation remains unconfirmed"), "verified bytes were presented as an OS open or installation result")
        require(acceptedMessage.contains("iOS accepted the request") && acceptedMessage.contains("Installation remains unconfirmed"), "OS open acceptance was presented as installation")
        require(rejectedMessage.contains("iOS rejected the request") && rejectedMessage.contains("Installation remains unconfirmed"), "OS open rejection lost its verified-but-uninstalled state")

        print("Shortcut package core contracts passed: canonical 0.3.0 official and approved self-host origins, redirect/status rejection, exact bytes and SHA-256, verified local file, and duplicate install gating.")
    }
}
