import Foundation

/// The command line of the policy-safety gate: `pca-policy-ci <files...> [options]` lints each file (a JSON policy document, or a JSON
/// array treated as a delegation chain), and `diff` / `test` / `coverage` run the authoring gates. Output goes to a `write` closure
/// (one line per call) and the exit code is returned: 0 pass, 1 a gate failed, 2 unusable input.
extension PCAPolicyCi {
    static let SEVERITIES = ["error", "warn", "info"]

    static let HELP = """
pca-policy-ci — statically catch unsafe PCA policies before they ship.

Usage:
  pca-policy-ci <files...> [options]
  pca-policy-ci diff <old.json> <new.json> [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]
  pca-policy-ci test <policy.json> <tests.json> [--require-digest]
  pca-policy-ci coverage <policy.json> <traffic-or-tests.json> [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]

Options:
  --max-severity <error|warn|info>  Lowest severity that fails the gate (default: error)
  --format <text|github>            Output format (default: text; 'github' = workflow annotations)
  --schema <file>                   Also check each policy against this signed action schema (JSON)
  --lint-rules-pin <file>           Fail unless the action-kit lint rule list has the digest in <file>
  --quiet, -q                       Only print findings and the summary line
  --help, -h                        Show this help

Each file is a JSON policy (Envelope / grant / compiled / { predicates, caveats }) or a JSON array
treated as a delegation chain. Exits non-zero when any finding is at or above --max-severity.
"""

    struct CliArgs {
        var files: [String] = []
        var maxSeverity = "error"
        var format = "text"
        var quiet = false
        var help = false
        var schema: String?
        var lintRulesPin: String?
        var json: V {
            A.obj([("files", PCADataflow.strs(files)), ("maxSeverity", .string(maxSeverity)), ("format", .string(format)), ("quiet", .bool(quiet)), ("help", .bool(help)),
                   ("schema", schema.map { .string($0) }), ("lintRulesPin", lintRulesPin.map { .string($0) })])
        }
    }

    enum Parsed {
        case args(CliArgs)
        case error(String)
        var json: V {
            switch self {
            case let .args(a): return .object(["args": a.json])
            case let .error(e): return .object(["error": .string(e)])
            }
        }
    }

    static func parseArgs(_ argv: [String]) -> Parsed {
        var a = CliArgs()
        var i = 0
        func isSeverity(_ x: String) -> Bool { has(SEVERITIES, x) }
        let sevErr = "--max-severity expects one of error|warn|info", fmtErr = "--format expects 'text' or 'github'"
        while i < argv.count {
            let x = argv[i]
            if IV.same(x, "--help") || IV.same(x, "-h") { a.help = true }
            else if IV.same(x, "--quiet") || IV.same(x, "-q") { a.quiet = true }
            else if IV.same(x, "--lint-rules-pin") {
                i += 1
                guard i < argv.count, !IV.startsWith(argv[i], "-") else { return .error("--lint-rules-pin expects a file") }
                a.lintRulesPin = argv[i]
            } else if IV.same(x, "--max-severity") {
                i += 1
                guard i < argv.count, isSeverity(argv[i]) else { return .error(sevErr) }
                a.maxSeverity = argv[i]
            } else if IV.startsWith(x, "--max-severity=") {
                let v = IV.dropPrefix(x, 15)
                guard isSeverity(v) else { return .error(sevErr) }
                a.maxSeverity = v
            } else if IV.same(x, "--schema") {
                i += 1
                guard i < argv.count else { return .error("--schema expects a file") }
                a.schema = argv[i]
            } else if IV.startsWith(x, "--schema=") { a.schema = IV.dropPrefix(x, 9) }
            else if IV.same(x, "--format") {
                i += 1
                guard i < argv.count, IV.same(argv[i], "text") || IV.same(argv[i], "github") else { return .error(fmtErr) }
                a.format = argv[i]
            } else if IV.startsWith(x, "--format=") {
                let v = IV.dropPrefix(x, 9)
                guard IV.same(v, "text") || IV.same(v, "github") else { return .error(fmtErr) }
                a.format = v
            } else if IV.startsWith(x, "-") { return .error("unknown option '\(x)'") }
            else { a.files.append(x) }
            i += 1
        }
        return .args(a)
    }

    /// `readFileSync(path, 'utf8')` relative to `dir`, with the platform's error text.
    static func readText(_ dir: String?, _ path: String) throws -> String {
        let full = (dir != nil && !path.hasPrefix("/")) ? dir! + "/" + path : path
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: full, isDirectory: &isDir) else { throw JSError("ENOENT: no such file or directory, open '\(path)'") }
        if isDir.boolValue { throw JSError("EISDIR: illegal operation on a directory, read") }
        guard let data = FileManager.default.contents(atPath: full) else { throw JSError("EACCES: permission denied, open '\(path)'") }
        return String(decoding: data, as: UTF8.self)
    }

    static func lintFile(_ dir: String?, _ file: String, _ schema: V?) throws -> [V] {
        let text: String
        do { text = try readText(dir, file) } catch { return [finding("malformed-policy", "error", "cannot read file: \((error as? JSError)?.message ?? "\(error)")")] }
        let doc: V
        do { doc = IV.normalized(try StrictJSON.parseLenient(text)) } catch { return [finding("malformed-policy", "error", "invalid JSON: \(error)")] }
        return try lint(doc, schema.map { .object(["schema": $0]) })
    }

    static let GH_LEVEL = ["error": "error", "warn": "warning", "info": "notice"]
    static let TEXT_TAG = ["error": "ERROR", "warn": "WARN ", "info": "INFO "]

    static func printText(_ results: [(label: String, findings: [V])], _ quiet: Bool, _ write: (String) -> Void) {
        for r in results {
            if !quiet { write("\n\(r.label):") }
            if r.findings.isEmpty { if !quiet { write("  (clean)") }; continue }
            for f in r.findings {
                let loc = mem(f, "where").map { " [\(s($0))]" } ?? ""
                write("  \(TEXT_TAG[s(mem(f, "severity"))] ?? s(mem(f, "severity"))) \(s(mem(f, "rule")))\(loc): \(s(mem(f, "message")))")
            }
        }
    }

    static func escapeGh(_ x: String) -> String {
        var out = String.UnicodeScalarView()
        for u in x.unicodeScalars {
            switch u {
            case "%": out.append(contentsOf: "%25".unicodeScalars)
            case "\r": out.append(contentsOf: "%0D".unicodeScalars)
            case "\n": out.append(contentsOf: "%0A".unicodeScalars)
            default: out.append(u)
            }
        }
        return String(out)
    }

    /// Workflow-command PROPERTY values must also escape `:` and `,`, or a file name can add properties or end the command.
    static func escapeGhProp(_ x: String) -> String {
        var out = String.UnicodeScalarView()
        for u in escapeGh(x).unicodeScalars {
            switch u {
            case ":": out.append(contentsOf: "%3A".unicodeScalars)
            case ",": out.append(contentsOf: "%2C".unicodeScalars)
            default: out.append(u)
            }
        }
        return String(out)
    }

    static func printGithub(_ results: [(label: String, findings: [V])], _ write: (String) -> Void) {
        for r in results {
            for f in r.findings {
                let props = "file=\(escapeGhProp(r.label)),title=\(escapeGhProp(s(mem(f, "rule"))))"
                let loc = mem(f, "where").map { "\(s($0)): " } ?? ""
                write("::\(GH_LEVEL[s(mem(f, "severity"))] ?? "error") \(props)::\(escapeGh("\(loc)\(s(mem(f, "message")))"))")
            }
        }
    }

    static func readJson(_ dir: String?, _ file: String) -> (doc: V?, reason: String?) {
        do { return (IV.normalized(try StrictJSON.parseLenient(try readText(dir, file))), nil) } catch { return (nil, "\(file): \((error as? JSError)?.message ?? "\(error)")") }
    }

    /// `Number(v)` for a flag value that must be a finite number.
    static func flagNum(_ flags: [(k: String, v: String?)], _ k: String) -> Double? {
        guard let e = flags.first(where: { IV.same($0.k, k) }), let v = e.v, !Attest.jsTrim(v).isEmpty else { return nil }
        let d = JS.numberFromString(v)
        return d.isFinite ? d : nil
    }

    /// `diff`, `test` and `coverage`: two files and flags. Unknown or malformed flags are a usage error (exit 2).
    static func runAuthoring(_ cmd: String, _ rest: [String], _ dir: String?, _ write: (String) -> Void) throws -> Int {
        var files: [String] = []
        var flags: [(k: String, v: String?)] = [] // insertion-ordered; nil = a boolean flag
        let valued = ["--verb", "--amount-field", "--window-secs", "--max-exposure-increase", "--min-clauses", "--min-boundaries", "--min-mutation", "--max-survivors"]
        let bools = ["--allow-widen", "--integer", "--require-digest"]
        func setFlag(_ k: String, _ v: String?) {
            if let i = flags.firstIndex(where: { IV.same($0.k, k) }) { flags[i].v = v } else { flags.append((k, v)) }
        }
        var i = 0
        while i < rest.count {
            let a = rest[i]
            if has(valued, a) {
                i += 1
                guard i < rest.count else { write("\(a) expects a value"); return 2 }
                setFlag(a, rest[i])
            } else if has(bools, a) { setFlag(a, nil) }
            else if IV.startsWith(a, "-") { write("unknown option '\(a)'"); return 2 }
            else { files.append(a) }
            i += 1
        }
        for f in flags where has(valued, f.k) && f.k != "--verb" && f.k != "--amount-field" && flagNum(flags, f.k) == nil {
            write("\(f.k) expects a number, got '\(f.v ?? "")'")
            return 2
        }
        if files.count != 2 {
            write("error: \(cmd) takes exactly two files")
            write(HELP)
            return 2
        }
        let docs = files.map { readJson(dir, $0) }
        if let failed = docs.first(where: { $0.reason != nil }) { write(failed.reason!); return 2 }
        let a = docs[0].doc, b = docs[1].doc
        func flag(_ k: String) -> String? { flags.first(where: { IV.same($0.k, k) })?.v }
        func has_(_ k: String) -> Bool { flags.contains { IV.same($0.k, k) } }
        func numV(_ k: String) -> V? { flagNum(flags, k).map { A.num($0) } }
        let r: V
        if cmd == "diff" {
            var o: JObject = ["allowWiden": .bool(has_("--allow-widen")), "integer": .bool(has_("--integer"))]
            if let v = flag("--verb") { o["verb"] = .string(v) }
            if let v = flag("--amount-field") { o["amountField"] = .string(v) }
            if let v = numV("--window-secs") { o["windowSecs"] = v }
            if let v = numV("--max-exposure-increase") { o["maxExposureIncrease"] = v }
            r = try diffCommand(a, b, .object(o))
        } else if cmd == "test" {
            r = try testCommand(a, b, .object(["requireDigest": .bool(has_("--require-digest"))]))
        } else {
            var o: JObject = [:]
            for (flagName, key) in [("--min-clauses", "minClauses"), ("--min-boundaries", "minBoundaries"), ("--min-mutation", "minMutation"), ("--max-survivors", "maxSurvivors")] {
                if let v = numV(flagName) { o[JKey(key)] = v }
            }
            r = try coverageCommand(a, b, .object(o))
        }
        for l in A.arr(mem(r, "lines")) { write(s(l)) }
        return Int(IV.int(mem(r, "exitCode")) ?? 2)
    }

    /// Runs the command line; `dir` is the directory relative file names are resolved in (nil: the working directory).
    static func run(_ argv: [String], dir: String? = nil, write: (String) -> Void) throws -> Int {
        if let f = argv.first, IV.same(f, "diff") || IV.same(f, "test") || IV.same(f, "coverage") { return try runAuthoring(f, Array(argv.dropFirst()), dir, write) }
        let args: CliArgs
        switch parseArgs(argv) {
        case let .error(e): write(e); write(HELP); return 2
        case let .args(a): args = a
        }
        if args.help { write(HELP); return 0 }
        var pinFailed = false
        if let pin = args.lintRulesPin {
            var ok = false, message = ""
            do {
                let r = try checkLintRulesPin(try readText(dir, pin))
                ok = mem(r, "ok") == .bool(true); message = s(mem(r, "message"))
            } catch { message = "cannot read the lint rules pin: \((error as? JSError)?.message ?? "\(error)")" }
            write("\(ok ? "PASS" : "FAIL") \u{2014} \(message)")
            pinFailed = !ok
            if args.files.isEmpty { return pinFailed ? 1 : 0 }
        }
        if args.files.isEmpty { write("error: no policy files given"); write(HELP); return 2 }
        var schema: V?
        if let sf = args.schema {
            let r = readJson(dir, sf)
            if let reason = r.reason { write(reason); return 2 }
            schema = r.doc
        }
        var results: [(label: String, findings: [V])] = []
        for f in args.files { results.append((f, try lintFile(dir, f, schema))) }
        let summary = try summarize(.array(results.map { .object(["label": .string($0.label), "findings": .array($0.findings)]) }), .object(["maxSeverity": .string(args.maxSeverity)]))
        if args.format == "github" { printGithub(results, write) } else { printText(results, args.quiet, write) }
        if let reason = mem(summary, "reason") { write("error: \(s(reason))") }
        let counts = mem(summary, "counts")
        write("\n\(mem(summary, "ok") == .bool(true) ? "PASS" : "FAIL") \u{2014} \(s(mem(counts, "error"))) error(s), \(s(mem(counts, "warn"))) warning(s), \(s(mem(counts, "info"))) info across \(results.count) policy/policies (fail threshold: \(args.maxSeverity))")
        let code = Int(IV.int(mem(summary, "exitCode")) ?? 2)
        return pinFailed ? max(1, code) : code
    }
}
