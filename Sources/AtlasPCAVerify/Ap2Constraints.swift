import Foundation
import CryptoKit

/// AP2 open-mandate constraint evaluation: a closed payment against an open payment mandate, a checkout against an open checkout mandate.
///
/// Stricter than the official AP2 SDK in four places, each a fail-closed choice: a line-item requirement with no acceptable items matches
/// nothing; the maximal flow must equal both the required and the carted quantity; a closed payment without `execution_date` is evaluated at
/// the verification time; `execution_date` bounds are compared as instants. Values are the reference's JSON shapes with JavaScript
/// semantics (a missing member is `nil`, a TypeError is a thrown `JSError`).
extension PCAAp2 {
    typealias V = JSONValue?

    // ---- JavaScript relational operators over JSON values ----

    /// ToPrimitive for the values JSON can hold: an array or object becomes its string form.
    static func prim(_ v: V) -> V {
        switch v {
        case .array?, .object?: return .string(JS.toString(v))
        default: return v
        }
    }

    /// Abstract relational comparison: -1, 0, 1, or nil when either side is NaN (every operator is then false).
    static func jsCmp(_ a0: V, _ b0: V) -> Int? {
        let a = prim(a0), b = prim(b0)
        if let x = a?.asString, let y = b?.asString {
            if x.utf16.elementsEqual(y.utf16) { return 0 }
            return x.utf16.lexicographicallyPrecedes(y.utf16) ? -1 : 1
        }
        let x = P.toNumber(a), y = P.toNumber(b)
        if x.isNaN || y.isNaN { return nil }
        return x < y ? -1 : (x > y ? 1 : 0)
    }

    static func jsLt(_ a: V, _ b: V) -> Bool { jsCmp(a, b).map { $0 < 0 } ?? false }
    static func jsGtV(_ a: V, _ b: V) -> Bool { jsCmp(a, b).map { $0 > 0 } ?? false }
    static func jsGe(_ a: V, _ b: V) -> Bool { jsCmp(a, b).map { $0 >= 0 } ?? false }
    static func jsLe(_ a: V, _ b: V) -> Bool { jsCmp(a, b).map { $0 <= 0 } ?? false }

    /// A JS number as a JSON value (NaN and Infinity stay doubles here: they print as `NaN` / `Infinity` in a message).
    static func numV(_ d: Double) -> JSONValue { d.isFinite ? P.num(d) : .double(d) }

    /// `x + v` for a number `x` and any JSON value (a string, array or object turns it into string concatenation).
    static func jsAdd(_ x: Double, _ v: V) -> JSONValue {
        switch v {
        case nil: return .double(.nan)
        case .null?: return numV(x)
        case let .bool(b)?: return numV(x + (b ? 1 : 0))
        case .int?, .double?: return numV(x + (P.numOf(v) ?? .nan))
        default: return .string(JS.toString(numV(x)) + JS.toString(v))
        }
    }

    /// `a ?? b` where `b` is only evaluated when `a` is nullish.
    static func coalesce(_ a: V, _ b: () throws -> V) rethrows -> V { P.nullish(a) ? try b() : a }

    // ---- merchants ----

    /// Whether `candidate` names the `target` merchant: by id when both carry one, else by name AND website.
    public static func merchantMatches(_ candidate: JSONValue?, _ target: JSONValue?) throws -> Bool {
        let cid = try P.prop(candidate, "id")
        if JS.truthy(cid) {
            let tid = try P.prop(target, "id")
            if JS.truthy(tid) { return P.seq(cid, tid) }
        }
        guard JS.truthy(try P.prop(candidate, "name")), JS.truthy(try P.prop(candidate, "website")) else { return false }
        return try P.seq(try P.prop(candidate, "name"), try P.prop(target, "name")) && P.seq(try P.prop(candidate, "website"), try P.prop(target, "website"))
    }

    /// `JSON.stringify(sortKeys(v))` (nil for `undefined`).
    static func sortedJson(_ v: V) -> String? {
        guard let x = v else { return nil }
        func sorted(_ y: JSONValue) -> JSONValue {
            switch y {
            case let .array(a): return .array(a.map(sorted))
            case let .object(o):
                // keys in code-unit order, positioned in that order (a parsed object's own positions would keep its written order)
                var out: JObject = [:]
                for k in o.keys.sorted(by: { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }) { out[o: k.s] = sorted(o[k]!) }
                return .object(out)
            default: return y
            }
        }
        return JS.stringify(sorted(x))
    }

    static func sameJson(_ a: V, _ b: V) -> Bool { sortedJson(a) == sortedJson(b) }

    // ---- RFC 3339 instants, independent of the host time zone ----

    static func daysFromCivil(_ y0: Int, _ m: Int, _ d: Int) -> Int {
        let y = m <= 2 ? y0 - 1 : y0
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146097 + doe - 719468
    }

    static func civilFromDays(_ z0: Int) -> (y: Int, m: Int, d: Int) {
        let z = z0 + 719468
        let era = (z >= 0 ? z : z - 146096) / 146097
        let doe = z - era * 146097
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
        let y = yoe + era * 400
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        return (m <= 2 ? y + 1 : y, m, d)
    }

    static func daysInMonth(_ y: Int, _ m: Int) -> Int {
        if m == 2 { return ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) ? 29 : 28 }
        return [4, 6, 9, 11].contains(m) ? 30 : 31
    }

    /// Epoch ms of an RFC 3339 instant, or nil. STRICT: `YYYY-MM-DD` (UTC midnight) or `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)` with
    /// every component in range (real calendar day, hour <= 23, no leap second; the fraction is truncated to ms).
    static func parseInstant(_ s: V) -> Double? {
        guard let str = s?.asString else { return nil }
        let b = Array(str.utf8)
        var i = 0
        func digits(_ n: Int) -> Int? {
            guard i + n <= b.count else { return nil }
            var v = 0
            for k in 0..<n {
                let c = b[i + k]
                guard c >= 0x30 && c <= 0x39 else { return nil }
                v = v * 10 + Int(c - 0x30)
            }
            i += n
            return v
        }
        func lit(_ c: UInt8) -> Bool { if i < b.count && b[i] == c { i += 1; return true }; return false }
        guard let y = digits(4), lit(0x2d), let mo = digits(2), lit(0x2d), let d = digits(2) else { return nil }
        guard mo >= 1, mo <= 12, d >= 1, d <= daysInMonth(y, mo) else { return nil }
        let day = Double(daysFromCivil(y, mo, d)) * 86_400_000
        if i == b.count { return day }
        guard lit(0x54), let h = digits(2), lit(0x3a), let mi = digits(2), lit(0x3a), let se = digits(2) else { return nil }
        var ms = 0
        if lit(0x2e) {
            let start = i
            while i < b.count, i - start < 9, b[i] >= 0x30, b[i] <= 0x39 { i += 1 }
            guard i > start else { return nil }
            var t = Array(b[start..<i].prefix(3))
            while t.count < 3 { t.append(0x30) }
            ms = t.reduce(0) { $0 * 10 + Int($1 - 0x30) }
        }
        var offset = 0.0
        if !lit(0x5a) {
            guard i < b.count, b[i] == 0x2b || b[i] == 0x2d else { return nil }
            let sign = b[i] == 0x2b ? 1.0 : -1.0
            i += 1
            guard let oh = digits(2), lit(0x3a), let om = digits(2) else { return nil }
            if oh > 23 || om > 59 { return nil }
            offset = sign * Double((oh * 60 + om) * 60_000)
        }
        guard i == b.count else { return nil }
        if h > 23 || mi > 59 || se > 59 { return nil }
        return day + Double(((h * 60 + mi) * 60 + se) * 1000 + ms) - offset
    }

    /// `Date.UTC(y, month0, d)` at midnight: the years 0..99 mean 1900..1999.
    static func dateUtc(_ y0: Int, _ month0: Int, _ d: Int) -> Double {
        var y = y0
        if y >= 0 && y <= 99 { y += 1900 }
        let q = month0 >= 0 ? month0 / 12 : -((-month0 + 11) / 12)
        y += q
        return Double(daysFromCivil(y, month0 - q * 12 + 1, d)) * 86_400_000
    }

    /// Start (epoch ms, UTC) of the calendar period of `frequency` that contains `ms`; nil for an unknown frequency, NaN for an invalid date.
    static func periodStart(_ ms: Double, _ frequency: V) -> Double? {
        guard let f = frequency?.asString else { return nil }
        if f == "ON_DEMAND" { return 0 }
        guard FREQUENCIES.contains(f) else { return nil }
        let t = ms.isFinite ? ms.rounded(.towardZero) : Double.nan
        if t.isNaN || abs(t) > 8.64e15 { return .nan }
        let days = Int((t / 86_400_000).rounded(.down))
        let (y, mo, d) = civilFromDays(days)
        let DAY = 86_400_000.0
        let day = dateUtc(y, mo - 1, d)
        let wd = ((days % 7) + 7 + 4) % 7 // getUTCDay, 0 = Sunday
        let weekStart = day - Double((wd + 6) % 7) * DAY
        switch f {
        case "DAILY": return day
        case "WEEKLY": return weekStart
        case "BIWEEKLY":
            let week = 7 * DAY, epochMonday = -3 * DAY
            return epochMonday + ((weekStart - epochMonday) / (2 * week)).rounded(.down) * 2 * week
        case "MONTHLY": return dateUtc(y, mo - 1, 1)
        case "QUARTERLY": return dateUtc(y, ((mo - 1) / 3) * 3, 1)
        case "ANNUALLY": return dateUtc(y, 0, 1)
        default: return nil
        }
    }

    // ---- payment constraints ----

    /// A usage context with a NaN, negative or fractional counter would make the cap comparisons fail open: refuse it.
    static func contextProblem(_ c: V) throws -> String? {
        let ta = try P.prop(c, "totalAmount"), tu = try P.prop(c, "totalUses"), last = try P.prop(c, "lastUsedDate")
        if !isNonNegInt(ta) || !isNonNegInt(tu) || (last != nil && !isNonNegInt(last)) {
            return "mandate context must carry non-negative integer totalAmount, totalUses and lastUsedDate"
        }
        return nil
    }

    static func listOf(_ v: V, _ what: String) throws -> [JSONValue] {
        guard case let .array(a)? = v else { throw JSError("\(what) is not a function") }
        return a
    }

    static func evaluatePayment(_ c: V, _ closed: V, _ o: V) throws -> [String] {
        let amt = try P.prop(closed, "payment_amount")
        let t = try P.prop(c, "type")
        let ctx = try P.prop(o, "context")
        switch t?.asString {
        case "payment.amount_range"?:
            var v: [String] = []
            let curC = try P.prop(c, "currency"), curA = try P.prop(amt, "currency")
            if !P.seq(curA, curC) { v.append("currency mismatch: expected \(P.tostr(curC)), got \(P.tostr(curA))") }
            let mn = try P.prop(c, "min")
            let amountV = try P.prop(amt, "amount")
            if !P.isFinite(amountV) { v.append("amount \(P.tostr(try P.prop(amt, "amount"))) is not finite") }
            if mn != nil, !jsGe(try P.prop(amt, "amount"), mn) { v.append("amount \(P.tostr(try P.prop(amt, "amount"))) below minimum \(P.tostr(mn))") }
            let mx = try P.prop(c, "max")
            if !jsLe(try P.prop(amt, "amount"), mx) { v.append("amount \(P.tostr(try P.prop(amt, "amount"))) exceeds maximum \(P.tostr(mx))") }
            return v
        case "payment.allowed_payees"?:
            for m in try listOf(try P.prop(c, "allowed"), "c.allowed.some") {
                if try merchantMatches(m, try P.prop(closed, "payee")) { return [] }
            }
            return ["payee \(P.tostr(try P.prop(try P.prop(closed, "payee"), "name"))) is not in the allowed list"]
        case "payment.allowed_payment_instruments"?:
            for i in try listOf(try P.prop(c, "allowed"), "c.allowed.some") {
                if P.seq(try P.prop(i, "id"), try P.prop(try P.prop(closed, "payment_instrument"), "id")) { return [] }
            }
            return ["payment instrument \(P.tostr(try P.prop(try P.prop(closed, "payment_instrument"), "id"))) is not in the allowed list"]
        case "payment.allowed_pisps"?:
            let p = try P.prop(closed, "pisp")
            if !JS.truthy(p) { return ["missing PISP in the closed mandate"] }
            for a in try listOf(try P.prop(c, "allowed"), "c.allowed.some") {
                if P.seq(try P.prop(a, "legal_name"), try P.prop(p, "legal_name")), P.seq(try P.prop(a, "brand_name"), try P.prop(p, "brand_name")),
                   P.seq(try P.prop(a, "domain_name"), try P.prop(p, "domain_name")) { return [] }
            }
            return ["PISP is not in the allowed list"]
        case "payment.reference"?:
            let h = try P.prop(o, "openCheckoutHash")
            if !JS.truthy(h) { return ["openCheckoutHash is required to evaluate a payment.reference constraint"] }
            let want = try P.prop(c, "conditional_transaction_id")
            return P.seq(h, want) ? [] : ["payment.reference does not match the open checkout mandate hash"]
        case "payment.budget"?:
            let curC = try P.prop(c, "currency"), curA = try P.prop(amt, "currency")
            if !P.seq(curA, curC) { return ["budget currency mismatch: expected \(P.tostr(curC)), got \(P.tostr(curA))"] }
            // The official SDK converts the budget with `int(max * 100)` for every currency; this reads it the same way, and the issuing side
            // (`ap2BudgetMax`) chooses `max` so that this reading is never above the PCA cap.
            if !JS.truthy(ctx) { return ["mandate context is required to evaluate a budget"] }
            if let bad = try contextProblem(ctx) { return [bad] }
            let scaled = P.toNumber(try P.prop(c, "max")) * 100
            let maxMinor = P.jsRound(scaled)
            if !(abs(scaled - maxMinor) <= 1e-6) { return ["budget.max is not a whole number of minor units"] }
            let past = try P.prop(ctx, "totalAmount")
            let spend = jsAdd(P.numOf(past) ?? 0, try P.prop(amt, "amount"))
            if !(P.isFinite(spend) && jsLe(spend, numV(maxMinor))) {
                return ["cumulative spend \(JS.toString(spend)) exceeds budget \(JS.toString(numV(maxMinor))) (past spend \(P.tostr(past)))"]
            }
            return []
        case "payment.agent_recurrence"?:
            var v: [String] = []
            // strict: an unknown frequency is a violation whether or not a last-used date exists
            if !(try P.prop(c, "frequency")?.asString.map { FREQUENCIES.contains($0) } ?? false) { return ["unknown recurrence frequency"] }
            if JS.truthy(ctx), let bad = try contextProblem(ctx) { return [bad] }
            let mo = try P.prop(c, "max_occurrences")
            if mo != nil {
                if !JS.truthy(ctx) { return ["mandate context is required to evaluate recurrence limits"] }
                let uses = try P.prop(ctx, "totalUses")
                if !jsLt(uses, mo) { v.append("maximum occurrences exceeded: \(P.tostr(uses)) >= \(P.tostr(mo))") }
            }
            let freq = try P.prop(c, "frequency")
            if !P.seq(freq, .string("ON_DEMAND")) {
                if !JS.truthy(ctx) { return ["mandate context is required to evaluate recurrence frequency"] }
                let last = try P.prop(ctx, "lastUsedDate")
                if last != nil {
                    let start = periodStart(P.toNumber(try P.prop(o, "now")) * 1000, freq)
                    if let s = start, !(P.toNumber(last) * 1000 < s) { v.append("already used in the current \(P.tostr(freq)) period") }
                }
            }
            return v
        case "payment.execution_date"?:
            let ed = try P.prop(closed, "execution_date")
            let nowMs = P.toNumber(try P.prop(o, "now")) * 1000
            let at: Double? = ed != nil ? parseInstant(ed) : nowMs
            guard let atv = at, atv.isFinite else { return ["execution_date \(P.tostr(ed)) is not a valid instant"] }
            var v: [String] = []
            for (key, before) in [("not_before", true), ("not_after", false)] {
                let bound = try P.prop(c, key)
                if bound == nil { continue }
                if let b = parseInstant(bound) {
                    if before ? !(atv >= b) : !(atv <= b) { v.append("execution date is \(before ? "before" : "after") the allowed window (\(key) \(P.tostr(bound)))") }
                } else {
                    v.append("\(key) \(P.tostr(bound)) is not a valid instant")
                }
            }
            return v
        default:
            return ["unknown constraint type \(P.tostr(t))"]
        }
    }

    /// Violations of the open payment mandate's constraints and pre-set claims by `closed` (empty = satisfied). `o`: `{ openCheckoutHash?,
    /// context? ({ totalAmount, totalUses, lastUsedDate? }), now }`.
    public static func checkPaymentConstraints(_ open: JSONValue?, _ closed: JSONValue?, _ o: JSONValue?) throws -> [String] {
        var v: [String] = []
        let payee = try P.prop(open, "payee")
        if payee != nil, !(try merchantMatches(payee, try P.prop(closed, "payee"))) {
            v.append("pre-set payee mismatch: expected \(P.tostr(try P.prop(payee, "name"))), got \(P.tostr(try P.prop(try P.prop(closed, "payee"), "name")))")
        }
        let pa = try P.prop(open, "payment_amount")
        if pa != nil, !sameJson(pa, try P.prop(closed, "payment_amount")) { v.append("pre-set payment_amount mismatch") }
        let pi = try P.prop(open, "payment_instrument")
        if pi != nil, !sameJson(pi, try P.prop(closed, "payment_instrument")) { v.append("pre-set payment_instrument mismatch") }
        let pisp = try P.prop(open, "pisp")
        if pisp != nil, !sameJson(pisp, try P.prop(closed, "pisp")) { v.append("pre-set pisp mismatch") }
        let ed = try P.prop(open, "execution_date")
        if ed != nil, !P.seq(ed, try P.prop(closed, "execution_date")) { v.append("pre-set execution_date mismatch") }

        let constraints = try listOf(try P.prop(open, "constraints"), "open.constraints.map")
        var types: [V] = []
        for c in constraints { types.append(try P.prop(c, "type")) }
        func has(_ s: String) -> Bool { types.contains { P.seq($0, .string(s)) } }
        if has("payment.agent_recurrence") {
            if !has("payment.amount_range") { v.append("payment.agent_recurrence requires a payment.amount_range constraint") }
            if !has("payment.budget") { v.append("payment.agent_recurrence requires a payment.budget constraint") }
        }
        for c in constraints { v.append(contentsOf: try evaluatePayment(c, closed, o)) }
        return v
    }

    // ---- checkout side ----

    /// Validate and project the checkout payload (`checkout_jwt`); throws a descriptive message when malformed. Returns the UCP Checkout slice
    /// `{ id, currency, line_items, totals, merchant? }`.
    public static func projectCheckout(_ payload: JSONValue?) throws -> JSONValue {
        func bad(_ m: String) -> JSError { JSError("checkout_jwt payload: \(m)") }
        let id = try P.prop(payload, "id"), cur = try P.prop(payload, "currency")
        guard let ids = id?.asString, !ids.isEmpty else { throw bad("id is required") }
        guard currencyOk(cur) else { throw bad("currency must be ISO 4217") }
        guard case let .array(lis)? = try P.prop(payload, "line_items"), !lis.isEmpty else { throw bad("line_items must be a non-empty array") }
        guard case let .array(totals)? = try P.prop(payload, "totals") else { throw bad("totals must be an array") }
        var lineItems: [JSONValue] = []
        for (i, li) in lis.enumerated() {
            guard case let .object(lo) = li, get(lo, "id")?.asString != nil, case let .object(item)? = get(lo, "item") else { throw bad("line_items[\(i)] is malformed") }
            if get(item, "id")?.asString == nil || get(item, "title")?.asString == nil || !isNonNegInt(get(item, "price")) {
                throw bad("line_items[\(i)].item needs id, title and integer minor-unit price")
            }
            if !isInt(get(lo, "quantity")) || (P.numOf(get(lo, "quantity")) ?? 0) < 1 { throw bad("line_items[\(i)].quantity must be a positive integer") }
            lineItems.append(.object(["id": get(lo, "id")!, "item": .object(["id": get(item, "id")!, "title": get(item, "title")!, "price": get(item, "price")!]), "quantity": get(lo, "quantity")!]))
        }
        var tt: [JSONValue] = []
        for (i, t) in totals.enumerated() {
            guard case let .object(to) = t, get(to, "type")?.asString != nil, isInt(get(to, "amount")) else { throw bad("totals[\(i)] is malformed") }
            tt.append(.object(["type": get(to, "type")!, "amount": get(to, "amount")!]))
        }
        var out: JObject = ["id": .string(ids), "currency": cur!, "line_items": .array(lineItems), "totals": .array(tt)]
        if let m = try P.prop(payload, "merchant") {
            guard case let .object(mo) = m, get(mo, "id")?.asString != nil, get(mo, "name")?.asString != nil else { throw bad("merchant needs id and name") }
            var merchant: JObject = ["id": get(mo, "id")!, "name": get(mo, "name")!]
            if let w = get(mo, "website"), w.asString != nil { merchant["website"] = w }
            out["merchant"] = .object(merchant)
        }
        return .object(out)
    }

    /// The checkout's single `total` entry in minor units, or nil when absent or ambiguous.
    public static func checkoutTotal(_ c: JSONValue?) throws -> JSONValue? {
        var t: [JSONValue] = []
        for x in try listOf(try P.prop(c, "totals"), "c.totals.filter") {
            if P.seq(try P.prop(x, "type"), .string("total")) { t.append(x) }
        }
        return t.count == 1 ? try P.prop(t[0], "amount") : nil
    }

    /// Maximal-flow assignment of cart quantities to requirement slots (Edmonds-Karp on the bipartite graph of the documentation): satisfied iff
    /// the flow equals both the required and the carted total. A quantity or sku that is not a number / string is refused (fail closed).
    static func lineItemViolations(_ cart: [JSONValue], _ reqs: [JSONValue]) throws -> [String] {
        func qtyOf(_ v: V) throws -> Double {
            guard let q = P.numOf(v), q.isFinite else { throw JSError("line item quantity is not a finite number") }
            return q
        }
        func skuOf(_ v: V) throws -> String {
            guard let s = v?.asString else { throw JSError("line item sku is not a string") }
            return s
        }
        var qty: [JKey: Double] = [:]
        var skus: [JKey] = []
        for li in cart {
            let k = JKey(try skuOf(try P.prop(try P.prop(li, "item"), "id")))
            if qty[k] == nil { skus.append(k) }
            qty[k] = (qty[k] ?? 0) + (try qtyOf(try P.prop(li, "quantity")))
        }
        let S = 0
        let T = 1 + skus.count + reqs.count
        var cap = [[Int: Double]](repeating: [:], count: T + 1)
        func add(_ u: Int, _ v: Int, _ c: Double) {
            cap[u][v] = (cap[u][v] ?? 0) + c
            cap[v][u] = cap[v][u] ?? 0
        }
        let INF = P.MAX_SAFE
        for (i, s) in skus.enumerated() { add(S, 1 + i, qty[s]!) }
        var required = 0.0
        for (j, r) in reqs.enumerated() {
            let rq = try qtyOf(try P.prop(r, "quantity"))
            required += rq
            add(1 + skus.count + j, T, rq)
            var ok = Set<JKey>()
            for a in try listOf(try P.prop(r, "acceptable_items"), "r.acceptable_items.map") { ok.insert(JKey(try skuOf(try P.prop(a, "id")))) }
            for (i, s) in skus.enumerated() where ok.contains(s) { add(1 + i, 1 + skus.count + j, INF) }
        }
        var flow = 0.0
        while true {
            var parent: [Int: Int] = [S: S]
            var queue = [S]
            var h = 0
            while h < queue.count && parent[T] == nil {
                let u = queue[h]
                h += 1
                for (v, c) in cap[u].sorted(by: { $0.key < $1.key }) where c > 0 && parent[v] == nil {
                    parent[v] = u
                    queue.append(v)
                }
            }
            if parent[T] == nil { break }
            var push = INF
            var v = T
            while v != S { push = min(push, cap[parent[v]!][v]!); v = parent[v]! }
            v = T
            while v != S {
                let u = parent[v]!
                cap[u][v] = cap[u][v]! - push
                cap[v][u] = cap[v][u]! + push
                v = u
            }
            flow += push
        }
        let carted = skus.reduce(0.0) { $0 + qty[$1]! }
        if flow == required && flow == carted { return [] }
        return ["line items do not satisfy the constraint: assigned \(JS.toString(numV(flow))) of \(JS.toString(numV(required))) required and \(JS.toString(numV(carted))) carted units"]
    }

    static func evaluateCheckout(_ c: V, _ checkout: V) throws -> [String] {
        let t = try P.prop(c, "type")
        if P.seq(t, .string("checkout.allowed_merchants")) {
            let m = try P.prop(checkout, "merchant")
            if !JS.truthy(m) { return ["missing merchant in the checkout"] }
            for a in try listOf(try P.prop(c, "allowed"), "c.allowed.some") {
                if try merchantMatches(a, m) { return [] }
            }
            return ["merchant \(P.tostr(try P.prop(m, "name"))) is not in the allowed list"]
        }
        if !P.seq(t, .string("checkout.line_items")) { return ["unknown constraint type \(P.tostr(t))"] }
        let items = try listOf(try P.prop(checkout, "line_items"), "checkout.line_items.length")
        if items.isEmpty { return ["empty cart does not satisfy a line_items constraint"] }
        return try lineItemViolations(items, try listOf(try P.prop(c, "items"), "c.items"))
    }

    /// Violations of the open checkout mandate's constraints by `checkout` (empty = satisfied).
    public static func checkCheckoutConstraints(_ open: JSONValue?, _ checkout: JSONValue?) throws -> [String] {
        var out: [String] = []
        for c in try listOf(try P.prop(open, "constraints"), "open.constraints.flatMap") { out.append(contentsOf: try evaluateCheckout(c, checkout)) }
        return out
    }
}
