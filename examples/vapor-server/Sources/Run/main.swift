import Foundation
import Vapor
import AtlasPCAVerify
import App

// PCA_AUDIENCE: the audience string agents sign for. PCA_GRANT_FILE: a file holding the principal's grant (JSON).
// PCA_MEDIATORS_FILE (optional): a JSON array of the agent-harness pins {mediator, kid, pk} whose provenance receipts you trust.
let env = ProcessInfo.processInfo.environment
guard let audience = env["PCA_AUDIENCE"], let file = env["PCA_GRANT_FILE"],
      let text = try? String(contentsOfFile: file, encoding: .utf8), let grant = JSONValue.parse(text) else {
    FileHandle.standardError.write(Data("set PCA_AUDIENCE and PCA_GRANT_FILE\n".utf8))
    exit(1)
}
let app = try await Application.make(.detect())
var mediators: [JSONValue] = []
if let path = env["PCA_MEDIATORS_FILE"] {
    guard let t = try? String(contentsOfFile: path, encoding: .utf8), case let .array(pins)? = JSONValue.parse(t) else {
        FileHandle.standardError.write(Data("PCA_MEDIATORS_FILE must hold a JSON array of pins\n".utf8))
        exit(1)
    }
    mediators = pins
}
try configure(app, audience: audience, grants: [grant], mediators: mediators)
try await app.execute()
try await app.asyncShutdown()
