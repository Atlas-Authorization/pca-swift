import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the action authoring forms (shorthands, expansion, loader, typed builders).
final class RefActionsAuthorTests: XCTestCase {
    func testAuthor() throws {
        try K042.requireCovers(["ActionAuthor", "Actions"])
        let d = Base.Diffs()
        try Base.each("ref-actions-author.json.gz") { c in
            let a0 = c.arg(0)
            let got: BaseGot
            func xs(_ i: Int) -> JObject? { i < c.args.count ? c.args[i].asObject : nil }
            func lng(_ v: JSONValue?) -> Int64? { v.flatMap { IV.int($0) } }
            switch c.fn {
            case "parseParamShorthand": got = RefActions.v { .object(try ActionAuthor.parseParamShorthand(a0?.asString ?? "")) }
            case "parseResourceShorthand": got = RefActions.v { .object(try ActionAuthor.parseResourceShorthand(a0?.asString ?? "")) }
            case "defaultTitle": got = .value(.string(ActionAuthor.defaultTitle(a0?.asString ?? "")))
            case "expandAction": got = RefActions.v { try ActionAuthor.expandAction(a0, c.arg(1)?.asString) }
            case "loadActionsValue": got = .value(ActionAuthor.loadActionsValue(a0))
            case "action": got = RefActions.v { try ActionAuthor.action(a0?.asString ?? "", c.arg(1)?.asObject) }
            case "builder":
                got = RefActions.v {
                    let kind = a0?.asString ?? ""
                    let a1 = c.arg(1)
                    let r: JObject
                    switch kind {
                    case "email": r = try ActionAuthor.P.email(xs(1))
                    case "phone": r = try ActionAuthor.P.phone(xs(1))
                    case "url": r = try ActionAuthor.P.url(xs(1))
                    case "uuid": r = try ActionAuthor.P.uuid(xs(1))
                    case "ccy": r = try ActionAuthor.P.ccy(xs(1))
                    case "country": r = try ActionAuthor.P.country(xs(1))
                    case "secret": r = try ActionAuthor.P.secret(xs(1))
                    case "bool": r = try ActionAuthor.P.bool(xs(1))
                    case "date": r = try ActionAuthor.P.date(xs(1))
                    case "datetime": r = try ActionAuthor.P.datetime(xs(1))
                    case "duration": r = try ActionAuthor.P.duration(lng(a1), xs(2))
                    case "message": r = try ActionAuthor.P.message(lng(a1), xs(2))
                    case "text": r = try ActionAuthor.P.text(lng(a1), xs(2))
                    case "int": r = try ActionAuthor.P.intRange(lng(a1), lng(c.arg(2)), xs(3))
                    case "count": r = try ActionAuthor.P.count(lng(a1), xs(2))
                    case "money": r = try ActionAuthor.P.money(a1, xs(2), xs(3))
                    case "id": r = try ActionAuthor.P.id(a1?.asString ?? "", xs(2))
                    case "enum": r = try ActionAuthor.P.enumOf(RefActions.list(a1).compactMap { $0.asString }, xs(2))
                    case "set": r = try ActionAuthor.P.setOf(RefActions.list(a1).compactMap { $0.asString }, xs(2))
                    case "array": r = try ActionAuthor.P.array(a1?.asString ?? "", lng(c.arg(2)), xs(3))
                    case "optional": r = ActionAuthor.P.optional(RefActions.obj(a1))
                    default: throw ActionKitError(code: "bad_builder", message: kind)
                    }
                    return .object(r)
                }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(480)
    }
}

/// Differential replay of the business rules block validation, the money and clock helpers, the rules digest and the signed rules review.
final class RefActionsRulesTests: XCTestCase {
    func testRules() throws {
        try K042.requireCovers(["ActionBusinessRules"])
        let d = Base.Diffs()
        try Base.each("ref-actions-rules.json.gz", seeds: true) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "businessRulesError": got = .value(Base.opt(ActionBusinessRules.businessRulesError(RefActions.obj(a0), a1)))
            case "businessRulesDigest": got = RefActions.v { .string(try ActionBusinessRules.businessRulesDigest(a0?.asString ?? "", RefActions.obj(a1))) }
            case "moneyOf": got = RefActions.v { try ActionBusinessRules.moneyOf(RefActions.obj(a0)) }
            case "minorUnits": got = RefActions.v { .int(try ActionBusinessRules.minorUnits(a0, Int(IV.int(a1) ?? 0), "x")) }
            case "clockAt": got = .value(ActionBusinessRules.clockAt(IV.num(a0) ?? Double.nan, a1?.asString) ?? .null)
            case "formatMoney": got = .value(.string(ActionBusinessRules.formatMoney(IV.int(a0) ?? 0, a1?.asString ?? "", Int(IV.int(c.arg(2)) ?? 0))))
            case "rulesReviewMessage": got = RefActions.v { Base.bytesValue(try ActionBusinessRules.rulesReviewMessage(RefActions.obj(a0))) }
            case "signRulesReview":
                got = RefActions.v {
                    guard let seed = Base.bytes(a1) else { throw ActionKitError(code: "bad_seed", message: "seed") }
                    return try ActionBusinessRules.signRulesReview(RefActions.obj(a0), try Ed25519Deterministic.key(seed: seed))
                }
            case "rulesReviewError": got = .value(Base.opt(ActionBusinessRules.rulesReviewError(a0, RefActions.obj(a1), RefActions.obj(c.arg(2)), c.arg(3))))
            case "compileBusinessRules": got = RefActions.v { .object(try ActionBusinessRules.compileBusinessRules(RefActions.obj(a0), rulesValue: a1)) }
            case "explainBusinessRules": got = RefActions.v { RefActions.strs(try ActionBusinessRules.explainBusinessRules(RefActions.obj(a0), rulesValue: a1)) }
            case "lintBusinessRules": got = RefActions.v { .array(try ActionBusinessRules.lintBusinessRules(RefActions.obj(a0), a1)) }
            case "runRuleExamples": got = RefActions.v { .array(try ActionBusinessRules.runRuleExamples(RefActions.obj(a0), rulesValue: a1)) }
            case "diffBusinessRules":
                got = RefActions.v {
                    .object(try ActionBusinessRules.diffBusinessRules(RefActions.obj(a0), try c.arg(1) == .null ? nil : RefActions.strictObj(a1), try c.arg(2) == .null ? nil : RefActions.strictObj(c.arg(2))))
                }
            case "evaluateBusinessRules": got = .value(.object(ActionBusinessRules.evaluateBusinessRules(RefActions.obj(a0), RefActions.obj(a1))))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(4000)
    }
}
