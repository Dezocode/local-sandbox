import Foundation

@main
enum WorkspaceCryptoContractTests {
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fatalError(message) }
    }

    static func noncanonicalFinalSextet(_ value: String) -> String {
        let replacements: [Character: Character] = ["A": "B", "Q": "R", "g": "h", "w": "x"]
        guard let last = value.last, let replacement = replacements[last] else {
            fatalError("Fixture does not end in a two-byte base64url canonical sextet.")
        }
        return String(value.dropLast()) + String(replacement)
    }

    static func main() throws {
        let fixture = #"{"recovery":{"format":"local-sandbox.workspace-recovery","version":1,"workspaceId":"06OXiZh8zBAZuzqOjFzjje9oEDra-ty2","epoch":"utF0s1clN1nve-6GmyFc4aMI","kdf":{"name":"PBKDF2","hash":"SHA-256","iterations":600000,"salt":"YbEXdmbGV4nP75wm0KAh2Q"},"cipher":{"name":"AES-GCM","iv":"hu-RMvkCPhJbKWcc","data":"dkDBLbhmNAjLMcA-ljFe6DpLUSdKEyC93lLlUCuFpzn9RIIJfF5g4yLQFQS8sEPJQ676KpATaNkqTDUL80FRX0IZHQ3nn8GwSlPHznEqqiwiTlV7HwiPjCng9Iq02dz6oiHSUey_2fZ5ZC0ZV8chILQ2Tycn90iJeMJZ6omD1Ui3HhTNwGak9OAQwLo9Fj6YsIlH9M6IMooOl7QeM6KONsiQeBkMnVzQNWa2Jco1Co2EiyaQmczD512740UyC2Xn2fQrzmNelYq4itX9PlzjQsZ6PHq_"}},"record":{"format":"local-sandbox.workspace-record","version":1,"workspaceId":"06OXiZh8zBAZuzqOjFzjje9oEDra-ty2","epoch":"utF0s1clN1nve-6GmyFc4aMI","recordId":"xfYI2Aw_DR9TweG_ZwgLJzfauCsllAX3IuYsns2_pvM","baseRevision":7,"mutationId":"mutation_0123456789abcdef","iv":"BwcHBwcHBwcHBwcH","data":"GxaTcx6GojwrruOOqm6G4UjhmDVdyHJw9tyvaJplY12k5jgpQef3ge6tOHGwEZ-q7u0AKPAGfVgW0KJEwssIqVrv1qYs7wAKGd2lq3bHD7sSxd7vYZrcS-cHLYlmcOaLyK324iDd_os099QZmoHfEEnYiUQ3fxzN47b7-XPdB2D0p3brWRzJtD-rbVhjMglDI_OzEt0vJ4MwOyIMTxLAp98vTskHRwXjqqjJxstXyF2nuB9M-yFTpmukpHG5NqZ3UU9Ug8K3GzWrEol5n0yxjKRnbLQe0pV5RzEwl6cvn21PUy_WABy0kNY7OUaMqKRCEWArdaCzuiC61G2ULy7tj7VKJejc8A087pnoBfzfDw"}}"#
        struct Fixture: Decodable { let recovery: WorkspaceRecoveryEnvelope; let record: EncryptedWorkspaceRecord }
        let decoded = try JSONDecoder().decode(Fixture.self, from: Data(fixture.utf8))
        let webSession = try WorkspaceCrypto.restore(decoded.recovery, passphrase: "correct horse battery staple")
        let webRecord = try WorkspaceCrypto.open(session: webSession, envelope: decoded.record)
        require(webRecord.path == "workspace/interop.txt", "Swift did not recover the Web Crypto path.")
        require(webRecord.content == "Swift ↔ Web Crypto", "Swift did not recover the Web Crypto content.")
        let interoperableRecordID = try WorkspaceCrypto.recordID(session: webSession, path: webRecord.path)
        require(interoperableRecordID == decoded.record.recordId, "Cross-platform record ID differs.")

        let v2Fixture = #"{"format":"local-sandbox.workspace-record","workspaceId":"06OXiZh8zBAZuzqOjFzjje9oEDra-ty2","epoch":"utF0s1clN1nve-6GmyFc4aMI","recordId":"-m8Ya8LVNf1pDOKNiE0Xxda0UAKOr6tYvIMoCXcuQxQ","baseRevision":8,"mutationId":"mutation_v2_0123456789abcdef","iv":"CQkJCQkJCQkJCQkJ","version":2,"data":"v48YcRitsy8obeP9uQwq_tFjO7oBp6bUj1xlR4Hy3KgrZZboRhq0b2f9EYl2W8sRPdHriqsot_g-fkMOPgfaNetC2gZphR2E6CJ7a9JvQRPq4JG3B1PGudcc68fV3J2OCtPeAckzRTUMxKX2tzW92AaTVGcWFGT4m7rVtrKU2zCcMjLFPvUHpsChPCc56OH_Hyrk4SIUcBD6K9XM2g7h0KzRH-7J8waqyTF5L90oyauIrKAk4ms5ThkNZvjPgx5wK4_eQBxiIgz0PnHV5NuAFQAM--kVSmiu3EBhgHb5UJpUvh9T0lYfy8xOVmm-AA-Px9xlD02R2VsdAB56KENQ6S2UW8X4SY1LegpuplB6fENx5DoHKPOv0Tb_I0pgp5xxRCDA09562R3T1NCI3hY"}"#
        let webV2 = try JSONDecoder().decode(EncryptedWorkspaceRecord.self, from: Data(v2Fixture.utf8))
        let openedWebV2 = try WorkspaceCrypto.open(session: webSession, envelope: webV2)
        require(openedWebV2.version == 2 && openedWebV2.path == "workspace/v2-interop.txt", "Swift did not authenticate the Web Crypto v2 payload.")
        require(openedWebV2.content == "Swift opens Web Crypto v2 \\ NUL:\0", "Swift did not decode canonical v2 UTF-8 content.")

        var tampered = decoded.record
        tampered = EncryptedWorkspaceRecord(format: tampered.format, version: tampered.version, workspaceId: tampered.workspaceId, epoch: tampered.epoch, recordId: tampered.recordId, baseRevision: 8, mutationId: tampered.mutationId, iv: tampered.iv, data: tampered.data)
        do { _ = try WorkspaceCrypto.open(session: webSession, envelope: tampered); fatalError("Tampered CAS metadata decrypted.") }
        catch {}

        let (nativeSession, recovery) = try WorkspaceCrypto.create(passphrase: "a different recovery phrase", createdAt: "2026-09-10T00:00:00Z")
        let restored = try WorkspaceCrypto.restore(recovery, passphrase: "a different recovery phrase")
        require(nativeSession.workspaceId == restored.workspaceId, "Native recovery changed workspace identity.")
        let beforeRotation = try WorkspaceCrypto.seal(session: restored, path: "workspace/rotation.txt", content: "same data key", baseRevision: nil, generation: 0, writerDevice: "device_0123456789abcdef")
        do { _ = try WorkspaceCrypto.rewrapRecovery(recovery, currentPassphrase: "a different recovery phrase", replacementPassphrase: "a different recovery phrase"); fatalError("Recovery rotation accepted the existing credential.") }
        catch let error as SandboxError { require(error.localizedDescription == "RECOVERY_REPLACEMENT_MUST_DIFFER", "same-credential rotation returned the wrong error") }
        let rotated = try WorkspaceCrypto.rewrapRecovery(recovery, currentPassphrase: "a different recovery phrase", replacementPassphrase: "replacement recovery phrase", createdAt: "2026-09-11T00:00:00Z")
        require(rotated.0.workspaceId == nativeSession.workspaceId && rotated.0.epoch == nativeSession.epoch, "Recovery rotation changed workspace identity or epoch.")
        require(rotated.1 != recovery, "Recovery rotation reused the old recovery envelope.")
        let openedAfterRotation = try WorkspaceCrypto.open(session: rotated.0, envelope: beforeRotation)
        require(openedAfterRotation.content == "same data key", "Recovery rotation changed the workspace data key.")
        do { _ = try WorkspaceCrypto.restore(rotated.1, passphrase: "a different recovery phrase"); fatalError("Old recovery phrase opened the rotated envelope.") }
        catch {}
        let restoredAfterRotation = try WorkspaceCrypto.restore(rotated.1, passphrase: "replacement recovery phrase")
        let recordIDAfterRotation = try WorkspaceCrypto.recordID(session: restoredAfterRotation, path: "workspace/rotation.txt")
        require(recordIDAfterRotation == beforeRotation.recordId, "Recovery rotation changed deterministic record identity.")
        let noncanonicalRecovery = WorkspaceRecoveryEnvelope(format: recovery.format, version: recovery.version, workspaceId: recovery.workspaceId, epoch: recovery.epoch, kdf: .init(name: recovery.kdf.name, hash: recovery.kdf.hash, iterations: recovery.kdf.iterations, salt: noncanonicalFinalSextet(recovery.kdf.salt)), cipher: recovery.cipher)
        do { _ = try WorkspaceCrypto.restore(noncanonicalRecovery, passphrase: "a different recovery phrase"); fatalError("Swift accepted a noncanonical base64url recovery envelope.") }
        catch {}
        let tombstone = try WorkspaceCrypto.seal(session: restored, path: "workspace/deleted.txt", content: nil, baseRevision: 4, generation: 2, writerDevice: "device_0123456789abcdef")
        let openedTombstone = try WorkspaceCrypto.open(session: nativeSession, envelope: tombstone)
        require(openedTombstone.content == nil && openedTombstone.contentSHA256 == nil, "Deletion did not round-trip as a tombstone.")
        let tombstoneObject = try JSONSerialization.jsonObject(with: JSONEncoder().encode(openedTombstone)) as! [String: Any]
        require(tombstoneObject.keys.contains("content") && tombstoneObject["content"] is NSNull, "Swift omitted the required null tombstone content field.")
        require(tombstoneObject.keys.contains("contentSHA256") && tombstoneObject["contentSHA256"] is NSNull, "Swift omitted the required null tombstone digest field.")
        let newRecord = try WorkspaceCrypto.seal(session: restored, path: "workspace/new.txt", content: "new", baseRevision: nil, generation: 0, writerDevice: "device_0123456789abcdef")
        require(newRecord.version == 2, "Swift emitted a legacy workspace payload instead of v2.")
        let newRecordObject = try JSONSerialization.jsonObject(with: JSONEncoder().encode(newRecord)) as! [String: Any]
        require(newRecordObject.keys.contains("baseRevision") && newRecordObject["baseRevision"] is NSNull, "Swift omitted the required null CAS revision field.")

        for (name, content) in [("empty", ""), ("nul", String(repeating: "\0", count: 64_000)), ("backslash", String(repeating: "\\", count: 64_000))] {
            let maximum = try WorkspaceCrypto.seal(session: restored, path: "workspace/\(name).txt", content: content, baseRevision: nil, generation: 0, writerDevice: "device_0123456789abcdef")
            require(maximum.version == 2 && maximum.data.count <= WorkspaceCrypto.maximumCiphertextCharacters, "Swift exceeded the bounded v2 ciphertext representation.")
            let maximumOpened = try WorkspaceCrypto.open(session: restored, envelope: maximum)
            require(maximumOpened.content == content, "Swift did not round-trip an exact 64,000-byte worst-case file.")
        }
        do {
            _ = try WorkspaceCrypto.seal(session: restored, path: "workspace/too-large.txt", content: String(repeating: "\0", count: 64_001), baseRevision: nil, generation: 0, writerDevice: "device_0123456789abcdef")
            fatalError("Swift accepted a file above the UTF-8 byte contract.")
        } catch {}

        var deviceBReview = WorkspaceReviewIndex()
        deviceBReview.replace([(path: "workspace/shared.txt", revision: 0, content: "base")])
        require(deviceBReview.decision(path: "workspace/shared.txt", current: .init(revision: 0, content: "base")) == .write(baseRevision: 0), "Device B could not write the exact revision it reviewed.")
        let deviceAWinner = WorkspaceReviewedBase(revision: 1, content: "device A change")
        require(deviceBReview.decision(path: "workspace/shared.txt", current: deviceAWinner) == .conflict(current: deviceAWinner), "Device B silently accepted device A's later revision.")
        require(deviceBReview.decision(path: "workspace/new.txt", current: nil) == .create, "A genuinely new path did not use create-only sync.")
        deviceBReview.remember(path: "workspace/shared.txt", revision: 2, content: nil)
        require(deviceBReview.decision(path: "workspace/shared.txt", current: .init(revision: 2, content: nil)) == .write(baseRevision: 2), "An authenticated tombstone was not retained as a reviewed base.")
        require(deviceBReview.decision(path: "workspace/shared.txt", current: nil) == .conflict(current: nil), "A reviewed tombstone could disappear without a conflict.")

        var unlockThenPush = WorkspaceReviewIndex()
        unlockThenPush.remember(path: "workspace/shared.txt", revision: 3, content: "previous session")
        unlockThenPush.clear()
        let unseenRemote = WorkspaceReviewedBase(revision: 4, content: "unseen remote")
        require(
            unlockThenPush.decision(path: "workspace/shared.txt", current: unseenRemote) == .conflict(current: unseenRemote),
            "Unlock followed by push could overwrite an existing remote value before comparison."
        )
        unlockThenPush.remember(path: "workspace/shared.txt", revision: unseenRemote.revision, content: unseenRemote.content)
        require(
            unlockThenPush.decision(path: "workspace/shared.txt", current: unseenRemote) == .write(baseRevision: unseenRemote.revision),
            "A displayed remote comparison did not establish the exact reviewed base."
        )

        do { _ = try WorkspaceCrypto.restore(recovery, passphrase: "the wrong recovery phrase"); fatalError("Wrong recovery phrase succeeded.") }
        catch {}

        let compactUnicodePassphrase = "🔐🔑🧩"
        let (unicodeSession, unicodeRecovery) = try WorkspaceCrypto.create(passphrase: compactUnicodePassphrase)
        let unicodeRestored = try WorkspaceCrypto.restore(unicodeRecovery, passphrase: compactUnicodePassphrase)
        require(unicodeRestored.workspaceId == unicodeSession.workspaceId, "UTF-8 byte passphrase policy rejected an interoperable Unicode value.")

        let embeddedNUL = "123456789012\0alpha"
        let (_, nulRecovery) = try WorkspaceCrypto.create(passphrase: embeddedNUL)
        do { _ = try WorkspaceCrypto.restore(nulRecovery, passphrase: "123456789012\0bravo"); fatalError("PBKDF2 truncated the passphrase at an embedded NUL byte.") }
        catch {}
        do { _ = try WorkspaceCrypto.create(passphrase: String(repeating: "x", count: 1_025)); fatalError("Oversized recovery passphrase succeeded.") }
        catch {}
        do {
            _ = try WorkspaceCrypto.seal(session: restored, path: "workspace/unsafe.txt", content: "unsafe", baseRevision: 9_007_199_254_740_992, generation: 0, writerDevice: "device_0123456789abcdef")
            fatalError("Revision outside the JavaScript safe integer range succeeded.")
        } catch {}
        do {
            _ = try WorkspaceCrypto.seal(session: restored, path: "workspace/unsafe.txt", content: "unsafe", baseRevision: nil, generation: 9_007_199_254_740_992, writerDevice: "device_0123456789abcdef")
            fatalError("Generation outside the JavaScript safe integer range succeeded.")
        } catch {}
        print("Workspace crypto contracts passed: v1/v2 Web Crypto interoperability, unlock-to-push review safety, reviewed-base conflicts, exact UTF-8 bounds, and tombstones.")
    }
}
