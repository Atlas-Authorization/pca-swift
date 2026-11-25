import Foundation

/// A `PCA-Action` header value that is not strict unpadded base64url of UTF-8 text (`code` is `invalid_pca_header`).
public struct PcaHeaderError: Error, CustomStringConvertible, Equatable {
    public let code = "invalid_pca_header"
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

/// One context segment a chat message adds.
public struct PCAMessageSegment: Equatable {
    /// `principal` (trusted) or `tool` (untrusted).
    public var origin: String
    public var source: String
    public var content: JSONValue
}

extension PCAAdapters {
    /// `PCA-Provenance: <base64url JSON>` for a bundle that fits `PCAIssue.PROVENANCE_HEADER_MAX`; empty otherwise (send it in the body as `pca_provenance`).
    public static func provenanceHeaders(_ bundle: JSONValue?) -> [String: String] {
        guard let b = bundle, let t = try? Canonical.canonicalizeStrict(b) else { return [:] }
        let v = Base64URLStrict.encode(Canonical.utf8(t))
        return v.count <= PCAIssue.PROVENANCE_HEADER_MAX ? [PCA.PROV_HEADER: v] : [:]
    }

    /// Reverse `PCAIssue.header`: a `PCA-Action` header value to the encoded PCActn JSON text. STRICT: unpadded RFC 4648 section 5 alphabet only, no whitespace,
    /// zero unused trailing bits, and the bytes must be valid UTF-8; anything else throws `PcaHeaderError`. Nothing is normalized.
    public static func decodePcaHeader(_ value: String) throws -> String {
        if value.isEmpty { throw PcaHeaderError("PCA-Action header is empty") }
        guard let bytes = Base64URLStrict.decode(value) else { throw PcaHeaderError("PCA-Action header is not strict unpadded base64url") }
        guard let text = String(bytes: bytes, encoding: .utf8) else { throw PcaHeaderError("PCA-Action header does not decode to UTF-8 text") }
        return text
    }

    private static let PRINCIPAL_ROLES: Set<String> = ["user", "human"]
    private static let MODEL_ROLES: Set<String> = ["assistant", "ai", "model", "system", "developer"]

    /// The context segments a chat message adds, by the conversation's own roles: a user / human turn is the PRINCIPAL (its text, and its other parts); a `tool_result`
    /// part inside any turn, a `tool` / `function` turn, and a turn of an unknown role are UNTRUSTED tool output; assistant / system turns add nothing (the model's
    /// output and the developer's prompt are not the principal's choice, and their values never count as principal text).
    public static func messageSegments(_ m: JSONValue?) -> [PCAMessageSegment] {
        guard let msg = m, msg.isObject else { return [] }
        let role = (msg.get("role")?.asString ?? msg.get("type")?.asString ?? "").lowercased()
        if MODEL_ROLES.contains(role) { return [] }
        let content = msg.get("content")
        func present(_ v: JSONValue?) -> JSONValue? { if let x = v, !x.isNull { return x }; return nil }
        func toolName(_ x: JSONValue) -> String {
            let v = present(x.get("toolName")) ?? present(x.get("name")) ?? present(x.get("tool_use_id")) ?? present(x.get("toolCallId")) ?? present(x.get("tool_call_id"))
                ?? present(msg.get("name")) ?? present(msg.get("tool_call_id"))
            return v.map { JS.toString($0) } ?? "tool"
        }
        if !PRINCIPAL_ROLES.contains(role) { return [PCAMessageSegment(origin: "tool", source: toolName(msg), content: present(content) ?? msg)] }
        guard case let .array(parts)? = content else { return [PCAMessageSegment(origin: "principal", source: "user", content: present(content) ?? .string(""))] }
        var out: [PCAMessageSegment] = []
        var text: [String] = []
        for part in parts {
            let pt: JSONValue = part.isObject ? part : .object(["type": .string("text"), "text": .string(JS.toString(part))])
            let t = pt.get("type")?.asString ?? ""
            if t == "tool_result" || t == "tool-result" || t == "function_call_output" {
                out.append(PCAMessageSegment(origin: "tool", source: toolName(pt), content: present(pt.get("content")) ?? present(pt.get("result")) ?? present(pt.get("output")) ?? pt))
            } else if let s = pt.get("text")?.asString { text.append(s) } else { out.append(PCAMessageSegment(origin: "principal", source: "user", content: pt)) }
        }
        if !text.isEmpty { out.insert(PCAMessageSegment(origin: "principal", source: "user", content: .string(text.joined(separator: "\n"))), at: 0) }
        return out
    }

    private static let seenLock = NSLock()
    private struct SeenEntry { weak var rec: ProvenanceRecorder?; var count: Int }
    // Weak-keyed by identity (NSMapTable is not in the Linux Foundation); dead recorders are pruned on each write.
    nonisolated(unsafe) private static var seen: [ObjectIdentifier: SeenEntry] = [:]

    /// Record a conversation's new messages in the provenance chain (call it with the whole message list before each model turn; messages already recorded are
    /// skipped, a shorter list starts over).
    public static func recordMessages(_ rec: ProvenanceRecorder, _ messages: [JSONValue]) throws {
        seenLock.lock()
        let from = seen[ObjectIdentifier(rec)].flatMap { $0.rec === rec ? $0.count : nil } ?? 0
        seenLock.unlock()
        let start = messages.count < from ? 0 : from
        for i in start..<messages.count {
            for seg in messageSegments(messages[i]) {
                if seg.origin == "principal" { try rec.principal(seg.content.asString ?? Canonical.canonicalize(seg.content)) } else { try rec.tool(seg.source, recordedText(seg.content)) }
            }
        }
        seenLock.lock()
        seen = seen.filter { $0.value.rec != nil }
        seen[ObjectIdentifier(rec)] = SeenEntry(rec: rec, count: messages.count)
        seenLock.unlock()
    }

    /// Record what the principal asked for: a string is the principal's message; a message list (or `{messages}`) is recorded with `recordMessages`; an object's
    /// `input` / `prompt` / `query` / `question` / `message` / `text` string (or message list) is the principal's message. Anything else records nothing (the gate then
    /// keeps the context at `agent`: fail closed).
    public static func recordInput(_ rec: ProvenanceRecorder?, _ input: JSONValue?) throws {
        guard let rec = rec, let input = input else { return }
        switch input {
        case let .string(s): try rec.principal(s)
        case let .array(a): try recordMessages(rec, a)
        case .object:
            if let ms = input.get("messages")?.asArray { try recordMessages(rec, ms) }
            for k in ["input", "prompt", "query", "question", "message", "text"] {
                guard let v = input.get(k) else { continue }
                if let s = v.asString { try rec.principal(s) } else if let a = v.asArray { try recordMessages(rec, a) }
            }
        default: break
        }
    }

    /// Wrap a framework entry point (`invoke`, `generateText`, `chat`, ...) so its first argument, the principal's request, is recorded before it runs.
    public static func withPrincipalInput<R>(_ agent: PCAFacadeAgent?, _ fn: @escaping (JSONValue) throws -> R) -> (JSONValue) throws -> R {
        return { input in
            try recordInput(agent?.provenance, input)
            return try fn(input)
        }
    }
}
