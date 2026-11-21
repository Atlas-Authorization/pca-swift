import Foundation

/// The agent side of the framework adapters, structurally: any tool that is `{metadata, call}` (the shape of a LlamaIndex FunctionTool, and of most
/// Swift tool types once mapped) is wrapped so every call first builds a PCActn (`PCAFacadeAgent.act`) -- fast-failing on the agent's local dry run and
/// handing the proof to `onProof` so it can be forwarded to the resource server -- then runs the original tool, and records what the tool returned in
/// the agent's provenance chain as UNTRUSTED. It does not authorize: the resource server's verifier decides; a bypassed wrapper only means the action
/// lacks a valid PCActn and fails there. `PCAMcp.pcaFetch` is the same for an MCP client transport.

/// Thrown when the agent's local dry run rejects a call before dispatch.
public struct PCADenied: Error, CustomStringConvertible, Equatable {
    public let reason: String
    public let verb: String
    public let resource: String
    public var description: String { "PCA denied \(verb) on \(resource): \(reason)" }
}

/// A tool call as a framework reports it.
public struct PCAToolCall {
    public var name: String
    public var arguments: JObject
    public init(name: String, arguments: JObject = [:]) {
        self.name = name
        self.arguments = arguments
    }
}

public enum PCAAdapters {
    /// The text a recorded value is committed as: a string as is, anything else its canonical JSON (key order independent).
    static func recordedText(_ v: JSONValue?) -> String {
        guard let v = v else { return "undefined" }
        if case let .string(s) = v { return s }
        return Canonical.canonicalize(v)
    }

    /// The principal's own message (TRUSTED).
    public static func recordPrincipal(_ agent: PCAFacadeAgent, _ text: String) throws { try agent.provenance.principal(text) }

    /// A tool result entering the model's context (UNTRUSTED).
    public static func recordToolResult(_ agent: PCAFacadeAgent, _ tool: String, _ output: JSONValue?) throws {
        try agent.provenance.tool(tool, recordedText(output))
    }

    /// How a framework tool name maps onto a PCA (verb, resource); nil = the call is sent without a proof.
    public typealias ToolMapping = (PCAToolCall) -> (verb: String, resource: String)?

    /// The proof for one framework tool call, from a name -> (verb, resource) mapping. nil when the mapping declines the call.
    public static func bridgeToolCall(_ agent: PCAFacadeAgent, _ call: PCAToolCall, _ map: ToolMapping, aud: String? = nil, counter: Int64? = nil, now: Int64? = nil) throws -> PCAActResult? {
        guard let m = map(call) else { return nil }
        return try agent.act(verb: m.verb, resource: m.resource, params: .object(call.arguments), options: PCAActOptions(counter: counter, aud: aud, now: now))
    }

    /// A tool's arguments and result are JSON values.
    public struct ToolSpec {
        /// The catalog verb the tool maps to (for example `stripe.refund`).
        public var verb: String
        /// The resource of a call: fixed, or derived from its arguments.
        public var resource: (JSONValue) -> String
        public var aud: String?
        /// Fast-fail on the local dry run before executing (default true).
        public var failFast: Bool
        /// Receives the PCActn so the call can forward it (for example as request headers) to the resource server.
        public var onProof: ((PCAActResult, JSONValue) -> Void)?
        public init(verb: String, resource: @escaping (JSONValue) -> String, aud: String? = nil, failFast: Bool = true, onProof: ((PCAActResult, JSONValue) -> Void)? = nil) {
            self.verb = verb
            self.resource = resource
            self.aud = aud
            self.failFast = failFast
            self.onProof = onProof
        }
        public init(verb: String, resource: String, aud: String? = nil, failFast: Bool = true, onProof: ((PCAActResult, JSONValue) -> Void)? = nil) {
            self.init(verb: verb, resource: { _ in resource }, aud: aud, failFast: failFast, onProof: onProof)
        }
    }

    /// Wrap `run(params, proof)` so every invocation first builds a PCActn, optionally fast-fails on the local dry run, then dispatches with the proof
    /// attached; what it returns is recorded as untrusted tool output.
    public static func guarded(_ agent: PCAFacadeAgent, _ spec: ToolSpec, _ run: @escaping (JSONValue, PCAActResult) async throws -> JSONValue) -> (JSONValue) async throws -> JSONValue {
        return { params in
            let resource = spec.resource(params)
            let act = try agent.act(verb: spec.verb, resource: resource, params: params, options: PCAActOptions(aud: spec.aud))
            if spec.failFast && !act.dryRun.allowed { throw PCADenied(reason: act.dryRun.reason ?? "denied", verb: spec.verb, resource: resource) }
            spec.onProof?(act, params)
            let out = try await run(params, act)
            try recordToolResult(agent, spec.verb, out)
            return out
        }
    }
}

/// A structural tool: `metadata` (name, description, parameters) and `call`. Every other member of the framework's own type stays with your mapping.
public struct PCATool {
    public var metadata: JSONValue
    public var call: (JSONValue) async throws -> JSONValue
    public init(metadata: JSONValue, call: @escaping (JSONValue) async throws -> JSONValue) {
        self.metadata = metadata
        self.call = call
    }
}

extension PCAAdapters {
    /// A copy of `tool` with the same metadata whose `call` first builds and attaches a PCActn (see `guarded`).
    public static func withPCA(_ agent: PCAFacadeAgent, _ spec: ToolSpec, _ tool: PCATool) -> PCATool {
        let run = guarded(agent, spec) { params, _ in try await tool.call(params) }
        return PCATool(metadata: tool.metadata, call: run)
    }
}

// MARK: MCP client transport

extension PCAMcp {
    public struct FetchRequest {
        public var url: String
        public var method: String
        public var headers: [String: String]
        public var body: String?
        public init(url: String, method: String = "GET", headers: [String: String] = [:], body: String? = nil) {
            self.url = url
            self.method = method
            self.headers = headers
            self.body = body
        }
    }

    public struct FetchResponse {
        public var status: Int
        public var headers: [String: String]
        /// The body text; nil for a stream the transport does not buffer.
        public var body: String?
        public init(status: Int, headers: [String: String] = [:], body: String? = nil) {
            self.status = status
            self.headers = headers
            self.body = body
        }
    }

    /// The JSON-RPC `tools/call` a request body carries: its tool name and arguments (a non-object `arguments` is `{}`); nil for anything else.
    static func toolCallOf(_ body: String?) -> PCAToolCall? {
        guard let b = body, let msg = JSONValue.parse(b), case let .object(o) = msg, o["method"] == .string("tools/call"),
              case let .object(p)? = o["params"], case let .string(name)? = p["name"] else { return nil }
        if case let .object(args)? = p["arguments"] { return PCAToolCall(name: name, arguments: args) }
        return PCAToolCall(name: name)
    }

    /// The agent side of an MCP server that requires a PCActn per tool call: a transport function that, for every JSON-RPC `tools/call` request,
    /// builds a fresh PCActn (verb and resource from `toolAction`, the arguments committed by digest, a new counter) and adds it as the `PCA-Action`
    /// header (and `PCA-Provenance` when it fits); every other request, and a call `toolAction` declines, passes through unchanged. The response of a
    /// `tools/call` is recorded in the agent's provenance chain as UNTRUSTED tool output before it is returned. It does not decide anything.
    public static func pcaFetch(_ agent: PCAFacadeAgent, _ toolAction: @escaping PCAAdapters.ToolMapping, aud: String? = nil,
                                fetch inner: @escaping (FetchRequest) async throws -> FetchResponse) -> (FetchRequest) async throws -> FetchResponse {
        return { req in
            guard let call = toolCallOf(req.body), let proof = try PCAAdapters.bridgeToolCall(agent, call, toolAction, aud: aud) else { return try await inner(req) }
            var out = req
            for (k, v) in proof.headers {
                for existing in Array(out.headers.keys) where existing.lowercased() == k.lowercased() { out.headers[existing] = nil }
                out.headers[k] = v
            }
            let res = try await inner(out)
            // a JSON body is recorded by its bytes; a stream is recorded at once by its origin (its label does not depend on its bytes)
            let ct = res.headers.first { $0.key.lowercased() == "content-type" }?.value ?? ""
            let content: JSONValue
            if !ct.lowercased().contains("event-stream"), let text = res.body { content = .string(text) } else {
                content = .object(["tool": .string(call.name), "stream": .string(req.url)])
            }
            try PCAAdapters.recordToolResult(agent, call.name, content)
            return res
        }
    }
}
