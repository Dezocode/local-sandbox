import Foundation
import CryptoKit
import CommonCrypto
import Security

struct EncryptedWorkspaceRecord: Codable, Equatable {
    let format: String
    let version: Int
    let workspaceId: String
    let epoch: String
    let recordId: String
    let baseRevision: Int?
    let mutationId: String
    let iv: String
    let data: String

    private enum CodingKeys: String, CodingKey {
        case format, version, workspaceId, epoch, recordId, baseRevision, mutationId, iv, data
    }

    init(format: String, version: Int, workspaceId: String, epoch: String, recordId: String, baseRevision: Int?, mutationId: String, iv: String, data: String) {
        self.format = format; self.version = version; self.workspaceId = workspaceId; self.epoch = epoch
        self.recordId = recordId; self.baseRevision = baseRevision; self.mutationId = mutationId; self.iv = iv; self.data = data
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard container.contains(.baseRevision) else { throw SandboxError.invalid("INVALID_WORKSPACE_RECORD") }
        format = try container.decode(String.self, forKey: .format)
        version = try container.decode(Int.self, forKey: .version)
        workspaceId = try container.decode(String.self, forKey: .workspaceId)
        epoch = try container.decode(String.self, forKey: .epoch)
        recordId = try container.decode(String.self, forKey: .recordId)
        baseRevision = try container.decodeIfPresent(Int.self, forKey: .baseRevision)
        mutationId = try container.decode(String.self, forKey: .mutationId)
        iv = try container.decode(String.self, forKey: .iv)
        data = try container.decode(String.self, forKey: .data)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(format, forKey: .format);try container.encode(version, forKey: .version)
        try container.encode(workspaceId, forKey: .workspaceId);try container.encode(epoch, forKey: .epoch)
        try container.encode(recordId, forKey: .recordId)
        if let baseRevision { try container.encode(baseRevision, forKey: .baseRevision) } else { try container.encodeNil(forKey: .baseRevision) }
        try container.encode(mutationId, forKey: .mutationId);try container.encode(iv, forKey: .iv);try container.encode(data, forKey: .data)
    }
}

struct WorkspaceRecoveryEnvelope: Codable, Equatable {
    struct KDF: Codable, Equatable {
        let name: String
        let hash: String
        let iterations: Int
        let salt: String
    }
    struct Cipher: Codable, Equatable {
        let name: String
        let iv: String
        let data: String
    }
    let format: String
    let version: Int
    let workspaceId: String
    let epoch: String
    let kdf: KDF
    let cipher: Cipher
}

struct WorkspaceRecord: Codable, Equatable {
    let version: Int
    let path: String
    let content: String?
    let contentSHA256: String?
    let generation: Int
    let writerDevice: String
    let writtenAt: String

    private enum CodingKeys: String, CodingKey {
        case version, path, content, contentSHA256, generation, writerDevice, writtenAt
    }

    init(version: Int, path: String, content: String?, contentSHA256: String?, generation: Int, writerDevice: String, writtenAt: String) {
        self.version = version;self.path = path;self.content = content;self.contentSHA256 = contentSHA256
        self.generation = generation;self.writerDevice = writerDevice;self.writtenAt = writtenAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard container.contains(.content), container.contains(.contentSHA256) else { throw SandboxError.invalid("INVALID_WORKSPACE_PAYLOAD") }
        version = try container.decode(Int.self, forKey: .version);path = try container.decode(String.self, forKey: .path)
        content = try container.decodeIfPresent(String.self, forKey: .content)
        contentSHA256 = try container.decodeIfPresent(String.self, forKey: .contentSHA256)
        generation = try container.decode(Int.self, forKey: .generation)
        writerDevice = try container.decode(String.self, forKey: .writerDevice);writtenAt = try container.decode(String.self, forKey: .writtenAt)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version);try container.encode(path, forKey: .path)
        if let content { try container.encode(content, forKey: .content) } else { try container.encodeNil(forKey: .content) }
        if let contentSHA256 { try container.encode(contentSHA256, forKey: .contentSHA256) } else { try container.encodeNil(forKey: .contentSHA256) }
        try container.encode(generation, forKey: .generation);try container.encode(writerDevice, forKey: .writerDevice);try container.encode(writtenAt, forKey: .writtenAt)
    }
}

struct WorkspaceCryptoSession {
    let workspaceId: String
    let epoch: String
    fileprivate let key: SymmetricKey
}

struct WorkspaceReviewedBase: Equatable {
    let revision: Int
    let content: String?
}

enum WorkspaceReviewDecision: Equatable {
    case create
    case write(baseRevision: Int)
    case conflict(current: WorkspaceReviewedBase?)
}

struct WorkspaceReviewIndex {
    private var reviewedByPath: [String: WorkspaceReviewedBase] = [:]

    mutating func replace(_ records: [(path: String, revision: Int, content: String?)]) {
        reviewedByPath.removeAll(keepingCapacity: true)
        for record in records {
            reviewedByPath[record.path] = WorkspaceReviewedBase(revision: record.revision, content: record.content)
        }
    }

    mutating func remember(path: String, revision: Int, content: String?) {
        reviewedByPath[path] = WorkspaceReviewedBase(revision: revision, content: content)
    }

    mutating func clear() { reviewedByPath.removeAll(keepingCapacity: false) }

    func decision(path: String, current: WorkspaceReviewedBase?) -> WorkspaceReviewDecision {
        guard let current else {
            return reviewedByPath[path] == nil ? .create : .conflict(current: nil)
        }
        guard reviewedByPath[path] == current else { return .conflict(current: current) }
        return .write(baseRevision: current.revision)
    }
}

enum WorkspaceCrypto {
    static let recordFormat = "local-sandbox.workspace-record"
    static let recoveryFormat = "local-sandbox.workspace-recovery"
    static let recoveryIterations = 600_000
    static let maximumContentBytes = 64_000
    static let maximumEncodedContentCharacters = 85_334
    static let legacyMaximumCiphertextCharacters = 100_000
    static let maximumCiphertextCharacters = 120_000
    private static let maximumSafeInteger = 9_007_199_254_740_991
    private static let encoder = JSONEncoder()
    private static let decoder = JSONDecoder()

    static func create(passphrase: String, createdAt: String = ISO8601DateFormatter().string(from: Date())) throws -> (WorkspaceCryptoSession, WorkspaceRecoveryEnvelope) {
        var raw = try random(count: 32)
        defer { raw.resetBytes(in: 0..<raw.count) }
        let workspaceId = base64URL(try random(count: 24))
        let epoch = base64URL(try random(count: 18))
        let session = try makeSession(workspaceId: workspaceId, epoch: epoch, raw: raw)
        return (session, try sealRecovery(workspaceId: workspaceId, epoch: epoch, raw: raw, passphrase: passphrase, createdAt: createdAt))
    }

    static func restore(_ envelope: WorkspaceRecoveryEnvelope, passphrase: String) throws -> WorkspaceCryptoSession {
        var raw = try openRecoveryKey(envelope, passphrase: passphrase)
        defer { raw.resetBytes(in: 0..<raw.count) }
        return try makeSession(workspaceId: envelope.workspaceId, epoch: envelope.epoch, raw: raw)
    }

    static func rewrapRecovery(
        _ envelope: WorkspaceRecoveryEnvelope,
        currentPassphrase: String,
        replacementPassphrase: String,
        createdAt: String = ISO8601DateFormatter().string(from: Date())
    ) throws -> (WorkspaceCryptoSession, WorkspaceRecoveryEnvelope) {
        guard currentPassphrase != replacementPassphrase else {
            throw SandboxError.invalid("RECOVERY_REPLACEMENT_MUST_DIFFER")
        }
        var raw = try openRecoveryKey(envelope, passphrase: currentPassphrase)
        defer { raw.resetBytes(in: 0..<raw.count) }
        let session = try makeSession(workspaceId: envelope.workspaceId, epoch: envelope.epoch, raw: raw)
        let replacement = try sealRecovery(
            workspaceId: envelope.workspaceId,
            epoch: envelope.epoch,
            raw: raw,
            passphrase: replacementPassphrase,
            createdAt: createdAt
        )
        return (session, replacement)
    }

    private static func openRecoveryKey(_ envelope: WorkspaceRecoveryEnvelope, passphrase: String) throws -> Data {
        do {
            try validate(envelope)
            guard let salt = decodeBase64URL(envelope.kdf.salt), salt.count == 16,
                  let nonceData = decodeBase64URL(envelope.cipher.iv), nonceData.count == 12,
                  let combined = decodeBase64URL(envelope.cipher.data), combined.count >= 16 else {
                throw SandboxError.invalid("INVALID_RECOVERY_ENVELOPE")
            }
            let key = try derive(passphrase: passphrase, salt: salt)
            var clear = try AES.GCM.open(try sealedBox(nonce: nonceData, ciphertextAndTag: combined), using: key, authenticating: aad(recoveryFormat, "1", envelope.workspaceId, envelope.epoch))
            defer { clear.resetBytes(in: 0..<clear.count) }
            let payload = try decoder.decode(RecoveryPayload.self, from: clear)
            guard payload.version == 1, payload.workspaceId == envelope.workspaceId, payload.epoch == envelope.epoch,
                  validTimestamp(payload.createdAt), var raw = decodeBase64URL(payload.workspaceKey) else {
                throw SandboxError.invalid("RECOVERY_IDENTITY_MISMATCH")
            }
            guard raw.count == 32 else {
                raw.resetBytes(in: 0..<raw.count)
                throw SandboxError.invalid("RECOVERY_IDENTITY_MISMATCH")
            }
            return raw
        } catch let error as SandboxError { throw error }
        catch { throw SandboxError.blocked("RECOVERY_PASSPHRASE_WRONG_OR_DAMAGED") }
    }

    static func recordID(session: WorkspaceCryptoSession, path rawPath: String) throws -> String {
        let path = try SandboxPath(rawPath).value
        let digest = HMAC<SHA256>.authenticationCode(for: aad(recordFormat, "1", session.workspaceId, session.epoch, path), using: session.key)
        return base64URL(Data(digest))
    }

    static func seal(session: WorkspaceCryptoSession, path rawPath: String, content: String?, baseRevision: Int?, generation: Int, writerDevice: String, mutationId: String? = nil, nonceData: Data? = nil, writtenAt: String = ISO8601DateFormatter().string(from: Date())) throws -> EncryptedWorkspaceRecord {
        let path = try SandboxPath(rawPath).value
        let revisionIsValid = baseRevision.map { (0...maximumSafeInteger).contains($0) } ?? true
        guard revisionIsValid,
              (0...maximumSafeInteger).contains(generation),
              validIdentifier(writerDevice), validTimestamp(writtenAt),
              content == nil || content!.utf8.count <= maximumContentBytes else { throw SandboxError.invalid("INVALID_WORKSPACE_RECORD") }
        let mutation: String
        if let mutationId { mutation = mutationId }
        else { mutation = base64URL(try random(count: 18)) }
        guard validIdentifier(mutation) else { throw SandboxError.invalid("INVALID_MUTATION_ID") }
        let nonceBytes = try nonceData ?? random(count: 12)
        guard nonceBytes.count == 12 else { throw SandboxError.invalid("INVALID_RECORD_NONCE") }
        let recordId = try recordID(session: session, path: path)
        let payload = WorkspaceRecordV2Payload(version: 2, path: path, contentUTF8: content.map { base64URL(Data($0.utf8)) }, contentSHA256: content.map(sha256), generation: generation, writerDevice: writerDevice, writtenAt: writtenAt)
        let nonce = try AES.GCM.Nonce(data: nonceBytes)
        let box = try AES.GCM.seal(encoder.encode(payload), using: session.key, nonce: nonce, authenticating: recordAAD(session: session, version: 2, recordId: recordId, baseRevision: baseRevision, mutationId: mutation))
        return EncryptedWorkspaceRecord(format: recordFormat, version: 2, workspaceId: session.workspaceId, epoch: session.epoch, recordId: recordId, baseRevision: baseRevision, mutationId: mutation, iv: base64URL(nonceBytes), data: base64URL(box.ciphertext + box.tag))
    }

    static func open(session: WorkspaceCryptoSession, envelope: EncryptedWorkspaceRecord) throws -> WorkspaceRecord {
        let revisionIsValid = envelope.baseRevision.map { (0...maximumSafeInteger).contains($0) } ?? true
        let maximumDataCharacters: Int
        switch envelope.version {
        case 1: maximumDataCharacters = legacyMaximumCiphertextCharacters
        case 2: maximumDataCharacters = maximumCiphertextCharacters
        default: maximumDataCharacters = 0
        }
        guard envelope.format == recordFormat, maximumDataCharacters > 0,
              envelope.workspaceId == session.workspaceId, envelope.epoch == session.epoch,
              validBase64URL(envelope.recordId, minimum: 43, maximum: 43), validIdentifier(envelope.mutationId),
              revisionIsValid,
              validBase64URL(envelope.iv, minimum: 16, maximum: 16),
              validBase64URL(envelope.data, minimum: 22, maximum: maximumDataCharacters),
              let nonceData = decodeBase64URL(envelope.iv), nonceData.count == 12,
              let combined = decodeBase64URL(envelope.data), combined.count >= 16 else {
            throw SandboxError.invalid("WORKSPACE_OR_EPOCH_MISMATCH")
        }
        do {
            let clear = try AES.GCM.open(try sealedBox(nonce: nonceData, ciphertextAndTag: combined), using: session.key, authenticating: recordAAD(session: session, version: envelope.version, recordId: envelope.recordId, baseRevision: envelope.baseRevision, mutationId: envelope.mutationId))
            let payload: WorkspaceRecord
            if envelope.version == 1 {
                payload = try decoder.decode(WorkspaceRecord.self, from: clear)
                guard payload.version == 1 else { throw SandboxError.invalid("INVALID_WORKSPACE_PAYLOAD") }
            } else {
                let encoded = try decoder.decode(WorkspaceRecordV2Payload.self, from: clear)
                guard encoded.version == 2 else { throw SandboxError.invalid("INVALID_WORKSPACE_PAYLOAD") }
                let content: String?
                if let contentUTF8 = encoded.contentUTF8 {
                    guard contentUTF8.count <= maximumEncodedContentCharacters,
                          let bytes = decodeBase64URL(contentUTF8), bytes.count <= maximumContentBytes,
                          base64URL(bytes) == contentUTF8,
                          let decoded = String(data: bytes, encoding: .utf8) else {
                        throw SandboxError.invalid("INVALID_WORKSPACE_PAYLOAD")
                    }
                    content = decoded
                } else {
                    content = nil
                }
                payload = WorkspaceRecord(version: 2, path: encoded.path, content: content, contentSHA256: encoded.contentSHA256, generation: encoded.generation, writerDevice: encoded.writerDevice, writtenAt: encoded.writtenAt)
            }
            guard try recordID(session: session, path: payload.path) == envelope.recordId,
                  (0...maximumSafeInteger).contains(payload.generation), validIdentifier(payload.writerDevice), validTimestamp(payload.writtenAt),
                  payload.content == nil ? payload.contentSHA256 == nil : payload.content!.utf8.count <= maximumContentBytes && payload.contentSHA256 == sha256(payload.content!) else { throw SandboxError.invalid("INVALID_WORKSPACE_PAYLOAD") }
            return payload
        } catch { throw SandboxError.blocked("WORKSPACE_RECORD_AUTHENTICATION_FAILED") }
    }

    private struct RecoveryPayload: Codable {
        let version: Int
        let workspaceId: String
        let epoch: String
        let workspaceKey: String
        let createdAt: String
    }

    private struct WorkspaceRecordV2Payload: Codable {
        let version: Int
        let path: String
        let contentUTF8: String?
        let contentSHA256: String?
        let generation: Int
        let writerDevice: String
        let writtenAt: String

        private enum CodingKeys: String, CodingKey {
            case version, path, contentUTF8, contentSHA256, generation, writerDevice, writtenAt
        }

        init(version: Int, path: String, contentUTF8: String?, contentSHA256: String?, generation: Int, writerDevice: String, writtenAt: String) {
            self.version = version;self.path = path;self.contentUTF8 = contentUTF8;self.contentSHA256 = contentSHA256
            self.generation = generation;self.writerDevice = writerDevice;self.writtenAt = writtenAt
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            guard container.contains(.contentUTF8), container.contains(.contentSHA256) else { throw SandboxError.invalid("INVALID_WORKSPACE_PAYLOAD") }
            version = try container.decode(Int.self, forKey: .version);path = try container.decode(String.self, forKey: .path)
            contentUTF8 = try container.decodeIfPresent(String.self, forKey: .contentUTF8)
            contentSHA256 = try container.decodeIfPresent(String.self, forKey: .contentSHA256)
            generation = try container.decode(Int.self, forKey: .generation)
            writerDevice = try container.decode(String.self, forKey: .writerDevice);writtenAt = try container.decode(String.self, forKey: .writtenAt)
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(version, forKey: .version);try container.encode(path, forKey: .path)
            if let contentUTF8 { try container.encode(contentUTF8, forKey: .contentUTF8) } else { try container.encodeNil(forKey: .contentUTF8) }
            if let contentSHA256 { try container.encode(contentSHA256, forKey: .contentSHA256) } else { try container.encodeNil(forKey: .contentSHA256) }
            try container.encode(generation, forKey: .generation);try container.encode(writerDevice, forKey: .writerDevice);try container.encode(writtenAt, forKey: .writtenAt)
        }
    }

    private static func makeSession(workspaceId: String, epoch: String, raw: Data) throws -> WorkspaceCryptoSession {
        guard validWorkspaceID(workspaceId), validIdentifier(epoch), raw.count == 32 else { throw SandboxError.invalid("INVALID_WORKSPACE_KEY") }
        return WorkspaceCryptoSession(workspaceId: workspaceId, epoch: epoch, key: SymmetricKey(data: raw))
    }

    private static func sealRecovery(workspaceId: String, epoch: String, raw: Data, passphrase: String, createdAt: String) throws -> WorkspaceRecoveryEnvelope {
        guard validTimestamp(createdAt) else { throw SandboxError.invalid("INVALID_RECOVERY_TIMESTAMP") }
        let salt = try random(count: 16), nonceData = try random(count: 12)
        let key = try derive(passphrase: passphrase, salt: salt)
        let payload = RecoveryPayload(version: 1, workspaceId: workspaceId, epoch: epoch, workspaceKey: base64URL(raw), createdAt: createdAt)
        let box = try AES.GCM.seal(encoder.encode(payload), using: key, nonce: AES.GCM.Nonce(data: nonceData), authenticating: aad(recoveryFormat, "1", workspaceId, epoch))
        return WorkspaceRecoveryEnvelope(format: recoveryFormat, version: 1, workspaceId: workspaceId, epoch: epoch, kdf: .init(name: "PBKDF2", hash: "SHA-256", iterations: recoveryIterations, salt: base64URL(salt)), cipher: .init(name: "AES-GCM", iv: base64URL(nonceData), data: base64URL(box.ciphertext + box.tag)))
    }

    private static func derive(passphrase: String, salt: Data) throws -> SymmetricKey {
        var password = Data(passphrase.utf8)
        guard (12...1_024).contains(password.count) else { throw SandboxError.invalid("RECOVERY_PASSPHRASE_LENGTH_INVALID") }
        defer { password.resetBytes(in: 0..<password.count) }
        var output = Data(count: 32)
        let outputCount = output.count
        let result = output.withUnsafeMutableBytes { outputBytes in
            salt.withUnsafeBytes { saltBytes in
                password.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passwordBytes.bindMemory(to: Int8.self).baseAddress, password.count, saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(recoveryIterations), outputBytes.bindMemory(to: UInt8.self).baseAddress, outputCount)
                }
            }
        }
        guard result == kCCSuccess else { throw SandboxError.blocked("RECOVERY_KDF_FAILED") }
        defer { output.resetBytes(in: 0..<output.count) }
        return SymmetricKey(data: output)
    }

    private static func sealedBox(nonce: Data, ciphertextAndTag: Data) throws -> AES.GCM.SealedBox {
        let split = ciphertextAndTag.count - 16
        return try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ciphertextAndTag.prefix(split), tag: ciphertextAndTag.suffix(16))
    }

    private static func recordAAD(session: WorkspaceCryptoSession, version: Int, recordId: String, baseRevision: Int?, mutationId: String) -> Data {
        aad(recordFormat, String(version), session.workspaceId, session.epoch, recordId, baseRevision.map(String.init) ?? "-", mutationId)
    }

    private static func aad(_ parts: String...) -> Data { Data(parts.joined(separator: "\0").utf8) }
    private static func sha256(_ value: String) -> String { SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined() }
    private static func validTimestamp(_ value: String) -> Bool {
        let standard = ISO8601DateFormatter()
        if standard.date(from: value) != nil { return true }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions.insert(.withFractionalSeconds)
        return fractional.date(from: value) != nil
    }
    private static func validBase64URL(_ value: String, minimum: Int, maximum: Int) -> Bool {
        (minimum...maximum).contains(value.count) && value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil
    }
    private static func validIdentifier(_ value: String) -> Bool { (16...64).contains(value.count) && value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil }
    private static func validWorkspaceID(_ value: String) -> Bool { value.count == 32 && value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil }

    private static func validate(_ envelope: WorkspaceRecoveryEnvelope) throws {
        guard envelope.format == recoveryFormat, envelope.version == 1, validWorkspaceID(envelope.workspaceId), validIdentifier(envelope.epoch),
              envelope.kdf.name == "PBKDF2", envelope.kdf.hash == "SHA-256", envelope.kdf.iterations == recoveryIterations,
              validBase64URL(envelope.kdf.salt, minimum: 22, maximum: 22),
              envelope.cipher.name == "AES-GCM", validBase64URL(envelope.cipher.iv, minimum: 16, maximum: 16),
              validBase64URL(envelope.cipher.data, minimum: 22, maximum: 4_096) else {
            throw SandboxError.invalid("INVALID_RECOVERY_ENVELOPE")
        }
    }

    private static func random(count: Int) throws -> Data {
        var value = Data(count: count)
        let status = value.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw SandboxError.blocked("SECURE_RANDOM_UNAVAILABLE") }
        return value
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        guard value.range(of: "^[A-Za-z0-9_-]*$", options: .regularExpression) != nil else { return nil }
        var normalized = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        normalized += String(repeating: "=", count: (4 - normalized.count % 4) % 4)
        guard let decoded = Data(base64Encoded: normalized), base64URL(decoded) == value else { return nil }
        return decoded
    }
}
