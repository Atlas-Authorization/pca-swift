import Foundation

/// JSON received from outside (signed or digested) read so that a repeated member is refused. `JSON.parse` keeps the LAST duplicate, so a signer and a verifier
/// could read different claims from the same bytes. The check looks at duplicates ONLY (any depth, keys compared after unescaping, scalar by scalar): numbers
/// and everything else stay as the sender wrote them (use `StrictJSON.parse` for formats this library defines).
public enum NoDuplicateKeys {
    /// The first key that a second member of the same object repeats, in text order; nil when there is none.
    public static func duplicateKey(_ text: String) -> String? {
        let b = Array(text.utf8)
        var keys: [Set<JKey>] = []
        var isObject: [Bool] = []
        var expectKey = false
        var i = 0
        while i < b.count {
            let c = b[i]
            if c == 0x22 {
                var j = i + 1
                while j < b.count && b[j] != 0x22 { j += b[j] == 0x5c ? 2 : 1 }
                if expectKey, isObject.last == true, j < b.count {
                    let raw = String(decoding: b[i...j], as: UTF8.self)
                    let key = (try? StrictJSON.parseLenientLastWins(raw))?.asString ?? raw
                    if keys[keys.count - 1].contains(JKey(key)) { return key }
                    keys[keys.count - 1].insert(JKey(key))
                    expectKey = false
                }
                i = j
            } else if c == 0x7b {
                keys.append([]); isObject.append(true); expectKey = true
            } else if c == 0x5b {
                keys.append([]); isObject.append(false); expectKey = false
            } else if c == 0x7d || c == 0x5d {
                if !keys.isEmpty { keys.removeLast(); isObject.removeLast() }
                expectKey = false
            } else if c == 0x2c {
                expectKey = isObject.last == true
            }
            i += 1
        }
        return nil
    }

    /// `JSON.parse` that refuses a duplicate member (message `duplicate key "k"`); numbers are read as written.
    public static func parse(_ text: String) throws -> JSONValue {
        let v: JSONValue
        do { v = try StrictJSON.parseLenientLastWins(text) } catch { throw JSError("\(error)") }
        if let k = duplicateKey(text) { throw JSError("duplicate key " + JS.stringify(.string(k))) }
        return v
    }
}
