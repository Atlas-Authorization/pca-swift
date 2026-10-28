import Foundation
import Vapor
import AtlasPCAVerify
import App

// PCA_AUDIENCE: the audience string agents sign for. PCA_GRANT_FILE: a file holding the principal's grant (JSON).
let env = ProcessInfo.processInfo.environment
guard let audience = env["PCA_AUDIENCE"], let file = env["PCA_GRANT_FILE"],
      let text = try? String(contentsOfFile: file, encoding: .utf8), let grant = JSONValue.parse(text) else {
    FileHandle.standardError.write(Data("set PCA_AUDIENCE and PCA_GRANT_FILE\n".utf8))
    exit(1)
}
let app = try await Application.make(.detect())
try configure(app, audience: audience, grants: [grant])
try await app.execute()
try await app.asyncShutdown()
