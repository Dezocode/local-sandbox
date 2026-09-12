import Foundation

@main
enum SandboxRecursiveContractTests {
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fatalError(message) }
    }

    static func main() throws {
        let manager = FileManager.default
        let root = manager.temporaryDirectory.appendingPathComponent("local-sandbox-recursive-\(UUID().uuidString)")
        let outside = manager.temporaryDirectory.appendingPathComponent("local-sandbox-outside-\(UUID().uuidString)")
        try manager.createDirectory(at: root.appendingPathComponent("workspace/nested/deeper"), withIntermediateDirectories: true)
        try manager.createDirectory(at: outside, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: root);try? manager.removeItem(at: outside) }
        try Data("exact".utf8).write(to: root.appendingPathComponent("workspace/nested/deeper/result.txt"))
        try Data("sibling".utf8).write(to: root.appendingPathComponent("workspace/nested/deeper/result.txt.bak"))
        try Data("hidden".utf8).write(to: root.appendingPathComponent("workspace/nested/.journal"))

        let paths = try SandboxRecursiveIndex.paths(root: root, folder: "workspace")
        require(paths.contains("workspace/nested/deeper/result.txt"), "nested file was omitted: \(paths)")
        require(paths.filter { $0 == "workspace/nested/deeper/result.txt" }.count == 1, "exact nested path was not unique")
        require(!paths.contains("workspace/nested/deeper/result"), "folder containment used a prefix instead of an exact normalized path")
        require(paths.contains("workspace/nested/deeper"), "nested directory was omitted")
        require(paths.contains("workspace/nested/.journal"), "valid hidden path regressed from direct folder listing")
        let regularFiles = try SandboxRecursiveIndex.regularFilePaths(root: root, folder: "workspace")
        require(regularFiles.contains("workspace/nested/deeper/result.txt"), "recursive file inventory omitted a nested regular file")
        require(!regularFiles.contains("workspace/nested/deeper"), "recursive file inventory exposed a directory as an editable file")

        do {
            _ = try SandboxRecursiveIndex.paths(root: root, folder: "workspace", maximumEntries: 2)
            fatalError("bounded recursive listing accepted too many entries")
        } catch let error as SandboxError {
            require(error.localizedDescription == "FOLDER_LIST_LIMIT", "recursive entry bound returned the wrong error")
        }

        try manager.createSymbolicLink(
            at: root.appendingPathComponent("workspace/outside-link"),
            withDestinationURL: outside.appendingPathComponent("secret.txt")
        )
        do {
            _ = try SandboxRecursiveIndex.paths(root: root, folder: "workspace")
            fatalError("recursive listing admitted a symlink outside the sandbox")
        } catch let error as SandboxError {
            require(error.localizedDescription == "SYMLINK_OUTSIDE_SANDBOX", "symlink escape returned the wrong error")
        }
        print("Recursive folder contracts passed: exact nested containment, bounded traversal, and symlink confinement.")
    }
}
