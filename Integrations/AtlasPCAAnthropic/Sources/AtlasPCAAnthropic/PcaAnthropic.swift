import Foundation
import SwiftAnthropic
import AtlasPCAVerify

/// PCA for jamesrochabrun/SwiftAnthropic. It does NOT authorize: it attaches a proof-carrying action to each `tool_use` block and the resource
/// server's verifier decides; a handler that forgets to forward the proof only means the downstream action lacks a valid PCActn and fails there.
/// Types are SwiftAnthropic's: `MessageResponse.Content.ToolUse` in, `MessageParameter.Message.Content.ContentObject.toolResult` out.
public enum PCAAnthropic {
    public typealias ToolUse = MessageResponse.Content.ToolUse
    public typealias ContentObject = MessageParameter.Message.Content.ContentObject

    /// Your tool: the model's input and the proof, so it can carry the proof downstream. nil result = `{"pca": <encoded>}`.
    public typealias Handler = (JSONValue, PCAActResult) async throws -> JSONValue?

    /// SwiftAnthropic's `DynamicContent` as a JSON value.
    public static func jsonValue(_ c: MessageResponse.Content.DynamicContent) -> JSONValue {
        switch c {
        case let .string(s): return .string(s)
        case let .integer(i): return .int(Int64(i))
        case let .double(d): return .double(d)
        case let .bool(b): return .bool(b)
        case .null: return .null
        case let .array(a): return .array(a.map(jsonValue))
        case let .dictionary(d): return jsonObject(d)
        }
    }

    /// A tool input (`[String: DynamicContent]`) as a JSON object.
    public static func jsonObject(_ input: MessageResponse.Content.Input) -> JSONValue {
        var o = JObject()
        for (k, v) in input { o[JKey(k)] = jsonValue(v) }
        return .object(o)
    }

    /// The `tool_use` blocks of an assistant message's content (text and other blocks are ignored).
    public static func extractToolUses(_ content: [MessageResponse.Content]) -> [ToolUse] {
        content.compactMap { if case let .toolUse(t) = $0 { return t } else { return nil } }
    }

    private static func result(_ id: String, _ text: String, isError: Bool?) -> ContentObject {
        .toolResult(id, [.text(text)], isError, nil)
    }

    /// Handle one `tool_use` block: build its PCActn, run the mapped handler and return the `tool_result`. A tool the mapping declines, or without a
    /// handler, is never run: an error `tool_result` tells Claude. A handler that throws returns an error `tool_result` too. The text that re-enters
    /// Claude's context (result or error) is recorded as untrusted.
    public static func handleToolUse(_ agent: PCAFacadeAgent, _ block: ToolUse, map: @escaping PCAAdapters.ToolMapping, handlers: [String: Handler],
                                     aud: String? = nil, counter: Int64? = nil, now: Int64? = nil) async throws -> ContentObject {
        let input = jsonObject(block.input)
        guard let proof = try PCAAdapters.bridgeToolCall(agent, PCAToolCall(name: block.name, arguments: input.asObjectValue), map, aud: aud, counter: counter, now: now) else {
            return result(block.id, "No proof-carrying authority is mapped for tool \"\(block.name)\".", isError: true)
        }
        guard let handler = handlers[block.name] else {
            return result(block.id, "No handler registered for tool \"\(block.name)\".", isError: true)
        }
        do {
            let out = try await handler(input, proof)
            let content = (out ?? .object(["pca": .string(proof.encoded)])).canonicalText
            try PCAAdapters.recordToolResult(agent, block.name, .string(content))
            return result(block.id, content, isError: nil)
        } catch {
            // a tool's error text reaches Claude too, and a tool can put anything in it
            let text = "\(error)"
            try PCAAdapters.recordToolResult(agent, block.name, .string(text))
            return result(block.id, text, isError: true)
        }
    }

    /// Handle many `tool_use` blocks (for example all of one assistant turn), in order.
    public static func handleToolUses(_ agent: PCAFacadeAgent, _ blocks: [ToolUse], map: @escaping PCAAdapters.ToolMapping, handlers: [String: Handler],
                                      aud: String? = nil, counter: Int64? = nil, now: Int64? = nil) async throws -> [ContentObject] {
        var out: [ContentObject] = []
        for (i, b) in blocks.enumerated() {
            out.append(try await handleToolUse(agent, b, map: map, handlers: handlers, aud: aud, counter: counter.map { $0 + Int64(i) }, now: now))
        }
        return out
    }
}

extension JSONValue {
    /// The members of an object value (empty for anything else).
    var asObjectValue: JObject { if case let .object(o) = self { return o } else { return [:] } }
}
