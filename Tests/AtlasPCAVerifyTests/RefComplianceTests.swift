import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCACompliance (audit events, the control-mapping table, per-framework reports and their renderers, the console
/// activity framework report) against the reference. A parsed object has no insertion order, so the corpus text is scanned once for each
/// object's member order (keyed by its member set) and handed to the port as its KeyOrder; the reference writes NaN / Infinity as {"$num"},
/// which the port renders as JSON null (as JSON.stringify does), so the expected side is mapped the same way.
final class RefComplianceTests: XCTestCase {
    static let file = "ref-compliance.json.gz"

    static func sig(_ keys: [String]) -> String {
        keys.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }.joined(separator: "\u{1}")
    }

    /// Member order of every object in a JSON text, by member set (an ambiguous set is dropped).
    static func scanOrders(_ b: [UInt8]) -> [String: [String]] {
        var orders: [String: [String]] = [:]
        var ambiguous = Set<String>()
        struct Frame { var isObj: Bool; var keys: [String] = []; var wantKey = false }
        var stack: [Frame] = []
        var i = 0
        func hex(_ c: UInt8) -> UInt32 {
            switch c {
            case 0x30...0x39: return UInt32(c) - 0x30
            case 0x61...0x66: return UInt32(c) - 0x61 + 10
            case 0x41...0x46: return UInt32(c) - 0x41 + 10
            default: return 0
            }
        }
        func readString() -> String {
            i += 1 // opening quote
            var units: [UInt16] = []
            while i < b.count, b[i] != 0x22 {
                if b[i] == 0x5C, i + 1 < b.count {
                    i += 1
                    switch b[i] {
                    case 0x6E: units.append(0x0A)
                    case 0x74: units.append(0x09)
                    case 0x72: units.append(0x0D)
                    case 0x62: units.append(0x08)
                    case 0x66: units.append(0x0C)
                    case 0x75:
                        if i + 4 < b.count {
                            units.append(UInt16(hex(b[i + 1]) << 12 | hex(b[i + 2]) << 8 | hex(b[i + 3]) << 4 | hex(b[i + 4])))
                            i += 4
                        }
                    default: units.append(UInt16(b[i]))
                    }
                    i += 1
                } else {
                    // raw UTF-8 run up to the next quote or backslash
                    var j = i
                    while j < b.count, b[j] != 0x22, b[j] != 0x5C { j += 1 }
                    units.append(contentsOf: String(decoding: b[i..<j], as: UTF8.self).utf16)
                    i = j
                }
            }
            i += 1 // closing quote
            return String(decoding: units, as: UTF16.self)
        }
        while i < b.count {
            switch b[i] {
            case 0x22:
                let s = readString()
                if let top = stack.last, top.isObj, top.wantKey { stack[stack.count - 1].keys.append(s); stack[stack.count - 1].wantKey = false }
            case 0x7B: stack.append(Frame(isObj: true, wantKey: true)); i += 1
            case 0x5B: stack.append(Frame(isObj: false)); i += 1
            case 0x2C:
                if let top = stack.last, top.isObj { stack[stack.count - 1].wantKey = true }
                i += 1
            case 0x7D, 0x5D:
                if let f = stack.popLast(), f.isObj {
                    let k = sig(f.keys)
                    if let prev = orders[k], prev != f.keys { ambiguous.insert(k) } else { orders[k] = f.keys }
                }
                i += 1
            default: i += 1
            }
        }
        for k in ambiguous { orders[k] = nil }
        return orders
    }

    static func norm(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map(norm))
        case let .object(o):
            if o.count == 1, o[JKey("$num")] != nil { return .null }
            return .object(o.mapValues(norm))
        default: return v
        }
    }

    func testCompliance() throws {
        try K042.requireCovers(["Compliance"])
        let orders = Self.scanOrders([UInt8](try K042.bytes(Self.file)))
        let order: PCACompliance.KeyOrder = { o in
            let keys = o.keys.map { $0.s }
            if let known = orders[Self.sig(keys)], Set(known) == Set(keys) { return known }
            return PCACompliance.defaultOrder(o)
        }
        let d = Base.Diffs()
        try Base.each(Self.file) { c0 in
            let c = BaseCase(fn: c0.fn, name: c0.name, args: c0.args, out: Self.norm(c0.out), suspect: c0.suspect, raw: c0.raw)
            let got: BaseGot
            switch c.fn {
            case "toAuditEvent": got = Base.run { try PCACompliance.toAuditEvent(c.arg(0), order: order) }
            case "constants": got = .value(PCACompliance.constants())
            case "controlMappings": got = Base.run { try PCACompliance.controlMappings(c.arg(0)) }
            case "toComplianceReport": got = Base.run { try PCACompliance.toComplianceReport(c.arg(0), c.arg(1)) }
            case "renderJson": got = Base.run { .string(try PCACompliance.renderJson(c.arg(0), order: order)) }
            case "renderMarkdown": got = Base.run { .string(try PCACompliance.renderMarkdown(c.arg(0))) }
            case "frameworkReport": got = Base.run { try PCACompliance.frameworkReport(c.arg(0), c.arg(1), c.arg(2)) }
            case "frameworkReportToMarkdown": got = Base.run { .string(try PCACompliance.frameworkReportToMarkdown(c.arg(0))) }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(900)
    }
}
