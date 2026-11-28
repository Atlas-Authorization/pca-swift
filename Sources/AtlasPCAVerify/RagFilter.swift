import Foundation

extension PCARag {
    /// A retriever wrapped so every result set is filtered to what the principal may see BEFORE it reaches the model, with the decision of the latest
    /// `retrieve` kept for audit (the reference's `FilteredRetriever`).
    public final class FilteredRetriever {
        private let retriever: (String, Int?) throws -> [JSONValue]
        private let principal: JSONValue?
        private let policy: JSONValue?
        private let recorder: ProvenanceRecorder?
        private let lock = NSLock()
        private var last: JSONValue?

        init(_ retriever: @escaping (String, Int?) throws -> [JSONValue], _ principal: JSONValue?, _ policy: JSONValue?, _ recorder: ProvenanceRecorder?) {
            self.retriever = retriever; self.principal = principal; self.policy = policy; self.recorder = recorder
        }

        /// The documents of `query` the principal may see. Dropped documents never reach the caller; every released one is recorded as untrusted retrieval
        /// provenance when a recorder is given.
        public func retrieve(_ query: String, _ k: Int? = nil) throws -> [JSONValue] {
            let docs = try retriever(query, k)
            let res = try PCARag.filterDocuments(principal: principal, candidates: docs, policy: policy)
            lock.lock(); last = res.decision; lock.unlock()
            if let rec = recorder {
                for (i, doc) in res.documents.enumerated() {
                    let id = doc.get("id")?.asString.flatMap { $0.isEmpty ? nil : $0 } ?? "doc#\(i)"
                    _ = try? rec.retrieval(id, PCAAdapters.recordedText(doc))
                }
            }
            return res.documents
        }

        /// The decision of the most recent `retrieve` (the proof trace), or nil if none yet.
        public func lastDecision() -> JSONValue? { lock.lock(); defer { lock.unlock() }; return last }
    }

    /// Wrap a generic retriever `(query, k) -> documents` (documents are `{id, acl?, tags?, ...}` objects) so every result set is filtered to what `principal`
    /// may see. The policy is compiled up front, so a malformed one throws here, not at the first query.
    public static func withPcaFilter(_ retriever: @escaping (String, Int?) throws -> [JSONValue], principal: JSONValue?, policy: JSONValue?, recorder: ProvenanceRecorder? = nil) throws -> FilteredRetriever {
        _ = try compilePolicy(policy)
        return FilteredRetriever(retriever, principal, policy, recorder)
    }
}
