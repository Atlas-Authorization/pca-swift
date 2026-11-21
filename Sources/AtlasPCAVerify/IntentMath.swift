import Foundation

/// Base-2 logarithm with the exact bit pattern of ECMAScript's Math.log2 (the fdlibm algorithm; the platform libm may round differently).
public enum PCAIntentMath {
    public static func log2(_ x0: Double) -> Double { FdLibm.log2(x0) }
}
