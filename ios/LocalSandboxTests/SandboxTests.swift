import XCTest
@testable import LocalSandbox
final class SandboxTests:XCTestCase {
    func testTraversalIsRejected() throws {for path in ["../secrets","workspace/../config/policy.json","/etc/passwd","workspace//notes","workspace/%2e%2e/x","workspace/a\\b"]{XCTAssertThrowsError(try SandboxPath(path))};XCTAssertNoThrow(try SandboxPath("workspace/notes.md"))}
    func testPatchRequiresExactlyOneMatch() throws {XCTAssertEqual(try exactPatch("Status: pending",old:"pending",replacement:"complete"),"Status: complete");XCTAssertThrowsError(try exactPatch("a a",old:"a",replacement:"b"));XCTAssertThrowsError(try exactPatch("aaa",old:"aa",replacement:"b"));XCTAssertThrowsError(try exactPatch("pending",old:"missing",replacement:"b"))}
    func testUnknownToolsCannotExecute() throws {XCTAssertThrowsError(try AgentAction.parse("{\"kind\":\"tool\",\"tool\":\"shell.exec\",\"arguments\":{}}"));XCTAssertThrowsError(try AgentAction.parse("```json\n{}\n```"))}
    func testStaleHashIsRequiredByEditContract() throws {XCTAssertThrowsError(try ToolCall(tool:.patch,arguments:["path":"workspace/a","old":"a","replacement":"b"]).validated())}
    func testBudgetValidation() throws {var policy=ResourcePolicy();policy.memoryTarget=100;XCTAssertThrowsError(try policy.validated())}
    func testPromptCap() {XCTAssertLessThanOrEqual(boundedPrompt(goal:String(repeating:"g",count:3000),capsule:String(repeating:"s",count:3000),latest:String(repeating:"x",count:10000),limit:2000).count,2000)}
}
