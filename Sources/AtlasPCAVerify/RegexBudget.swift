import Foundation

/// The regex work budget (the reference's `RegexBudget`, `withRegexBudget`, `chargeRegex`). There are two layers:
///  - a DOCUMENT budget (opened by every library entry point that evaluates a document: `decide`, `evaluatePredicates`, caveats, prohibitions, contracts): the per-document
///    caps, fresh per document so a verdict is a pure function of (document, subject);
///  - an optional REQUEST budget (`PCARegexBudget.request()`, `run`), opened by the server once per HTTP request: every document budget opened inside it ALSO charges the
///    request budget, whose caps are `REGEX_REQUEST_SCALE` documents' worth.
/// Charging happens BEFORE matching; once a cap would be exceeded the budget is poisoned and every later evaluation is refused (the caller treats it as no match or
/// unknown, i.e. fail closed). The open scope is per thread (a scope must not span a thread hop).
///
/// DIFFERENCE from the reference: a library entry point nested in an open DOCUMENT scope opens its own document budget chained to the open scope (the reference joins the
/// open document); the open scope is therefore charged as well, so the nested evaluation is refused no later than the reference would refuse it.
public final class PCARegexBudget {
    public static let MAX_REGEX_EVALUATIONS_PER_DOCUMENT = SafeRegex.MAX_REGEX_EVALUATIONS_PER_DOCUMENT
    public static let MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT = SafeRegex.MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT
    public static let MAX_REGEX_STEPS_PER_DOCUMENT = SafeRegex.MAX_REGEX_STEPS_PER_DOCUMENT
    /// A request-level budget allows this many documents' worth of regex work in total.
    public static let REGEX_REQUEST_SCALE = 4

    public internal(set) var evaluations = 0
    public internal(set) var chars = 0
    public internal(set) var steps = 0
    /// Evaluations refused so far (a veto or guard must treat a refusal as "could not decide").
    public internal(set) var refusals = 0
    let scale: Int
    /// The enclosing budget this one also charges (nil for a top-level budget).
    public let parentBudget: PCARegexBudget?
    public let isDocument: Bool
    /// The request's source (the server's client key).
    public let source: String?

    /// A document budget chained to the open scope (if any).
    public init() { self.scale = 1; self.parentBudget = PCARegexBudget.open; self.isDocument = true; self.source = nil }

    init(scale: Int, parent: PCARegexBudget?, isDocument: Bool, source: String?) {
        self.scale = scale; self.parentBudget = parent; self.isDocument = isDocument; self.source = source
    }

    /// A request-scoped budget: run the request's regex-evaluating sections through `run`.
    public static func request(source: String? = nil) -> PCARegexBudget { PCARegexBudget(scale: REGEX_REQUEST_SCALE, parent: nil, isDocument: false, source: source) }

    /// Charge one evaluation (`srcUnits` pattern UTF-16 units, `progLen` compiled instructions, `subjectUnits` subject UTF-16 units); false = refused.
    func charge(srcUnits: Int, progLen: Int, subjectUnits: Int) -> Bool {
        let ev = evaluations + 1
        let ch = chars + srcUnits
        let st = steps + progLen * (subjectUnits + 1)
        if ev > SafeRegex.MAX_REGEX_EVALUATIONS_PER_DOCUMENT * scale || ch > SafeRegex.MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT * scale || st > SafeRegex.MAX_REGEX_STEPS_PER_DOCUMENT * scale
            || (parentBudget != nil && !parentBudget!.charge(srcUnits: srcUnits, progLen: progLen, subjectUnits: subjectUnits)) {
            // poison the budget so a later, cheaper pattern cannot sneak in after an over-budget one (order-independent refusal)
            evaluations = SafeRegex.MAX_REGEX_EVALUATIONS_PER_DOCUMENT * scale + 1
            refusals += 1
            return false
        }
        evaluations = ev
        chars = ch
        steps = st
        return true
    }

    /// Charge one evaluation of `src` against a subject of `subjectLen` UTF-16 units; false = refused (the caller must NOT match). A pattern outside the safe subset is refused.
    public func charge(_ src: String, subjectLen: Int) -> Bool {
        let u = Array(src.utf16)
        guard SafeRegex.isSafeSource(u), let re = SafeRegex.compile(u) else { refusals += 1; return false }
        return charge(srcUnits: u.count, progLen: re.prog.count, subjectUnits: subjectLen)
    }

    private static let slot = "atlas.pca.regex.budget"

    /// The open scope of this thread.
    static var open: PCARegexBudget? {
        get { Thread.current.threadDictionary[slot] as? PCARegexBudget }
        set { Thread.current.threadDictionary[slot] = newValue }
    }

    /// Make this the open scope for `fn` (restores the previous scope afterwards).
    public func run<T>(_ fn: () throws -> T) rethrows -> T {
        let prev = PCARegexBudget.open
        PCARegexBudget.open = self
        defer { PCARegexBudget.open = prev }
        return try fn()
    }

    /// Run `fn` as ONE document. With an explicit `budget` it runs inside that budget. Otherwise, if a document scope is already open it joins it; else it opens a fresh
    /// document budget chained to the enclosing request budget if there is one.
    public static func withRegexBudget<T>(_ budget: PCARegexBudget? = nil, _ fn: () throws -> T) rethrows -> T {
        if let b = budget { return try b.run(fn) }
        if let cur = open, cur.isDocument { return try fn() }
        return try PCARegexBudget(scale: 1, parent: open, isDocument: true, source: nil).run(fn)
    }

    /// The open scope's refusal count (0 outside a scope). A before/after difference tells a guard that a match was REFUSED.
    public static func regexRefusals() -> Int { open?.refusals ?? 0 }

    /// Charge one regex evaluation to the open scope; outside any scope it is charged to a fresh single-use budget (so it is still bounded; it just shares nothing).
    public static func chargeRegex(_ src: String, subjectLen: Int) -> Bool { (open ?? PCARegexBudget()).charge(src, subjectLen: subjectLen) }

    /// The source (client key) of the innermost open budget, walking document budgets up to the request budget.
    public static func currentRegexSource() -> String? {
        var b = open
        while let x = b { if let s = x.source { return s }; b = x.parentBudget }
        return nil
    }
}
