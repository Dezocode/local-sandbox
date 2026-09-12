import Foundation

enum SandboxRecursiveIndex {
    static func paths(
        root: URL,
        folder: String,
        manager: FileManager = .default,
        maximumEntries: Int = 1_000,
        maximumDepth: Int = 32
    ) throws -> [String] {
        try entries(
            root: root,
            folder: folder,
            manager: manager,
            maximumEntries: maximumEntries,
            maximumDepth: maximumDepth
        ).map(\.path)
    }

    static func regularFilePaths(
        root: URL,
        folder: String,
        manager: FileManager = .default,
        maximumEntries: Int = 1_000,
        maximumDepth: Int = 32
    ) throws -> [String] {
        try entries(
            root: root,
            folder: folder,
            manager: manager,
            maximumEntries: maximumEntries,
            maximumDepth: maximumDepth
        ).filter(\.isRegularFile).map(\.path)
    }

    private static func entries(
        root: URL,
        folder: String,
        manager: FileManager,
        maximumEntries: Int,
        maximumDepth: Int
    ) throws -> [(path: String, isRegularFile: Bool)] {
        guard ["workspace", "config", "state", "logs", "output"].contains(folder),
              maximumEntries > 0, maximumDepth > 0 else { throw SandboxError.invalid("INVALID_FOLDER") }
        let displayRoot = root.standardizedFileURL
        let directory = displayRoot.appendingPathComponent(folder).standardizedFileURL
        let canonicalRoot = displayRoot.resolvingSymlinksInPath().standardizedFileURL
        let canonicalDirectory = directory.resolvingSymlinksInPath().standardizedFileURL
        guard canonicalDirectory.path.hasPrefix(canonicalRoot.path + "/") else { throw SandboxError.invalid("SYMLINK_OUTSIDE_SANDBOX") }
        guard let enumerator = manager.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey],
            options: []
        ) else { throw SandboxError.blocked("FOLDER_LIST_UNAVAILABLE") }
        var result: [(path: String, isRegularFile: Bool)] = []
        var visited = 0
        while let candidate = enumerator.nextObject() as? URL {
            visited += 1
            guard visited <= maximumEntries else { throw SandboxError.blocked("FOLDER_LIST_LIMIT") }
            let values = try candidate.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey])
            let depth = enumerator.level
            let relative = candidate.pathComponents.suffix(depth).joined(separator: "/")
            guard depth <= maximumDepth else {
                if values.isDirectory == true { enumerator.skipDescendants() }
                throw SandboxError.blocked("FOLDER_DEPTH_LIMIT")
            }
            if values.isSymbolicLink == true {
                let resolved = candidate.resolvingSymlinksInPath().standardizedFileURL
                guard resolved.path.hasPrefix(canonicalRoot.path + "/") else {
                    throw SandboxError.invalid("SYMLINK_OUTSIDE_SANDBOX")
                }
                if values.isDirectory == true { enumerator.skipDescendants() }
            }
            if values.isRegularFile == true || values.isDirectory == true || values.isSymbolicLink == true {
                let normalized = folder + "/" + relative
                _ = try SandboxPath(normalized)
                result.append((path: normalized, isRegularFile: values.isRegularFile == true && values.isSymbolicLink != true))
            }
        }
        return result.sorted { $0.path < $1.path }
    }
}
