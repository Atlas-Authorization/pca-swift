import Foundation

extension Dictionary where Key == JKey, Value == JSONValue {
    /// Member access that records INSERTION order for objects built in code: a member set through `o[o: "name"] = v` gets the next position after the
    /// members already there (a parsed object's positions are 1...n, so a parsed object extended this way continues its order), and `JS.keyOrder`,
    /// `YamlEmit` and `JS.stringify` then list the members as a JavaScript object would, not in code-unit order. Re-setting a member keeps its position;
    /// setting nil removes it. Members set through plain `JKey` subscripts carry no position and still follow the positioned ones in code-unit order.
    subscript(o name: String) -> JSONValue? {
        get { self[JKey(name)] }
        set {
            if let i = index(forKey: JKey(name)) {
                let stored = self[i].key
                if let v = newValue { self[stored] = v } else { removeValue(forKey: stored) }
            } else if let v = newValue {
                var next: Int32 = 0
                for k in keys where k.ord > next { next = k.ord }
                self[JKey(name, ord: next + 1)] = v
            }
        }
    }
}
