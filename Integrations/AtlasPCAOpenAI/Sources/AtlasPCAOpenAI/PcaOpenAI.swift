import Foundation
import OpenAI
import AtlasPCAVerify

/// PCA for MacPaw/OpenAI chat completions. It does NOT authorize: it attaches a proof-carrying action to each tool call and the resource server's
/// verifier decides (an over-cap or out-of-policy call still produces a signed PCActn here and is refused server-side). Types are MacPaw/OpenAI's:
/// the model's `ChatQuery.ChatCompletionMessageParam.AssistantMessageParam.ToolCallParam` in, a `ChatQuery.ChatCompletionMessageParam.tool(...)` out.
public enum PCAOpenAI {
    public typealias ToolCall = ChatQuery.ChatCompletionMessageParam.AssistantMessageParam.ToolCallParam
    public typealias Message = ChatQuery.ChatCompletionMessageParam

    /// Runs the real tool: the parsed arguments and the proof, so it can forward the proof to the resource server. nil result = `{"pca": <encoded>}`.
    public typealias Handler = (JSONValue, PCAActResult) async throws -> JSONValue?

    public struct DispatchError: Error, CustomStringConvertible {
        public let description: String
    }

    /// A tool call's `arguments` (a JSON string; empty or whitespace is `{}`) as the JSON object it must be.
    static func parseArguments(_ raw: String) throws -> JSONValue {
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return .object([:]) }
        guard let v = JSONValue.parse(t) else { throw DispatchError(description: "dispatchToolCall: tool_call arguments are not JSON") }
        guard case .object = v else { throw DispatchError(description: "dispatchToolCall: tool_call arguments must be a JSON object") }
        return v
    }

    /// Dispatch one tool call: build and sign a PCActn, run the mapped handler with it and return the `tool` message for the next turn. Throws when
    /// `map` declines the tool: a tool without a PCActn is never run.
    public static func dispatchToolCall(_ agent: PCAFacadeAgent, _ call: ToolCall, map: @escaping PCAAdapters.ToolMapping, handlers: [String: Handler],
                                        aud: String? = nil, counter: Int64? = nil, now: Int64? = nil) async throws -> Message {
        let name = call.function.name
        let args = try parseArguments(call.function.arguments)
        guard let proof = try PCAAdapters.bridgeToolCall(agent, PCAToolCall(name: name, arguments: args.asObjectValue), map, aud: aud, counter: counter, now: now) else {
            throw DispatchError(description: "dispatchToolCall: no PCActn for unmapped tool \"\(name)\" (the mapping declined)")
        }
        let result = try await handlers[name]?(args, proof)
        let content = (result ?? .object(["pca": .string(proof.encoded)])).canonicalText
        // the tool message re-enters the model's context: untrusted from here on (provenance by default)
        try PCAAdapters.recordToolResult(agent, name, .string(content))
        return .tool(.init(content: .textContent(content), toolCallId: call.id))
    }

    /// Dispatch the tool calls of one model turn in order; `counter`, when given, is incremented per call so each PCActn carries a distinct counter.
    public static func dispatchToolCalls(_ agent: PCAFacadeAgent, _ calls: [ToolCall], map: @escaping PCAAdapters.ToolMapping, handlers: [String: Handler],
                                         aud: String? = nil, counter: Int64? = nil, now: Int64? = nil) async throws -> [Message] {
        var out: [Message] = []
        for (i, c) in calls.enumerated() {
            out.append(try await dispatchToolCall(agent, c, map: map, handlers: handlers, aud: aud, counter: counter.map { $0 + Int64(i) }, now: now))
        }
        return out
    }

    /// Records a conversation's new messages in the agent's provenance chain before a model turn: `user` turns are the principal (their text; a
    /// list of parts contributes its text parts), `tool` turns are untrusted tool output; assistant, system and developer turns add nothing.
    /// Messages already recorded are skipped; a shorter list starts over.
    public final class Conversation: @unchecked Sendable {
        let agent: PCAFacadeAgent
        private var seen = 0
        private let lock = NSLock()
        public init(_ agent: PCAFacadeAgent) { self.agent = agent }

        public func record(_ messages: [Message]) throws {
            lock.lock()
            defer { lock.unlock() }
            if messages.count < seen { seen = 0 }
            for m in messages[seen...] {
                switch m {
                case let .user(u):
                    switch u.content {
                    case let .string(s): try PCAAdapters.recordPrincipal(agent, s)
                    case let .contentParts(parts):
                        let text = parts.compactMap { part -> String? in if case let .text(t) = part { return t.text } else { return nil } }
                        if !text.isEmpty { try PCAAdapters.recordPrincipal(agent, text.joined(separator: "\n")) }
                    }
                case let .tool(t):
                    let text: String
                    switch t.content {
                    case let .textContent(s): text = s
                    case let .contentParts(parts): text = parts.map { $0.text }.joined(separator: "\n")
                    }
                    try PCAAdapters.recordToolResult(agent, t.toolCallId, .string(text))
                default: break
                }
            }
            seen = messages.count
        }
    }
}

extension JSONValue {
    /// The members of an object value (empty for anything else).
    var asObjectValue: JObject { if case let .object(o) = self { return o } else { return [:] } }
}
