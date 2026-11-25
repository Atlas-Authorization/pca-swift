import Foundation

/// The fdlibm algorithms behind the reference runtime's Math.log / exp / sin / log2, with the fused multiply-adds its arm64 build uses,
/// so the doubles are bit-identical to the reference (the platform libm may round differently by an ulp).
public enum FdLibm {
    @inline(__always) private static func hi(_ x: Double) -> Int32 { Int32(truncatingIfNeeded: x.bitPattern >> 32) }
    @inline(__always) private static func lo(_ x: Double) -> UInt32 { UInt32(truncatingIfNeeded: x.bitPattern) }
    @inline(__always) private static func withHi(_ x: Double, _ h: Int32) -> Double {
        Double(bitPattern: (UInt64(UInt32(bitPattern: h)) << 32) | (x.bitPattern & 0xffff_ffff))
    }
    @inline(__always) private static func withLoZero(_ x: Double) -> Double { Double(bitPattern: x.bitPattern & 0xffff_ffff_0000_0000) }
    /// x * a + b, rounded once.
    @inline(__always) private static func mad(_ x: Double, _ a: Double, _ b: Double) -> Double { b.addingProduct(x, a) }

    private static let two54: Double = 1.8014398509481984e16
    private static let ln2Hi: Double = 6.93147180369123816490e-01
    private static let ln2Lo: Double = 1.90821492927058770002e-10
    private static let lg1: Double = 6.666666666666735130e-01
    private static let lg2: Double = 3.999999999940941908e-01
    private static let lg3: Double = 2.857142874366239149e-01
    private static let lg4: Double = 2.222219843214978396e-01
    private static let lg5: Double = 1.818357216161805012e-01
    private static let lg6: Double = 1.531383769920937332e-01
    private static let lg7: Double = 1.479819860511658591e-01

    /// `Math.log`.
    public static func log(_ x0: Double) -> Double {
        var x = x0
        var hx = hi(x)
        let lx = lo(x)
        var k: Int32 = 0
        if hx < 0x0010_0000 {
            if (UInt32(bitPattern: hx & 0x7fff_ffff) | lx) == 0 { return -Double.infinity }
            if hx < 0 { return Double.nan }
            k -= 54
            x *= two54
            hx = hi(x)
        }
        if hx >= 0x7ff0_0000 { return x + x }
        k += (hx >> 20) - 1023
        hx &= 0x000f_ffff
        var i: Int32 = (hx + 0x95f64) & 0x10_0000
        x = withHi(x, hx | (i ^ 0x3ff0_0000))
        k += i >> 20
        let f = x - 1.0
        if (0x000f_ffff & (2 + hx)) < 3 {
            if f == 0.0 {
                if k == 0 { return 0.0 }
                let dk = Double(k)
                return mad(dk, ln2Hi, dk * ln2Lo)
            }
            let r = f * f * mad(-0.33333333333333333, f, 0.5)
            if k == 0 { return f - r }
            let dk = Double(k)
            return mad(dk, ln2Hi, -(mad(-dk, ln2Lo, r) - f))
        }
        let s = f / (2.0 + f)
        let dk = Double(k)
        let z = s * s
        i = hx - 0x6147a
        let w = z * z
        let j: Int32 = 0x6b851 - hx
        let t1 = w * mad(w, mad(w, lg6, lg4), lg2)
        let t2 = z * mad(w, mad(w, mad(w, lg7, lg5), lg3), lg1)
        i |= j
        let r = t2 + t1
        if i > 0 {
            let hfsq = 0.5 * f * f
            if k == 0 { return f - mad(-s, hfsq + r, hfsq) }
            return mad(dk, ln2Hi, -((hfsq - mad(s, hfsq + r, dk * ln2Lo)) - f))
        } else if k == 0 {
            return mad(-s, f - r, f)
        } else {
            return mad(dk, ln2Hi, -((mad(s, f - r, -(dk * ln2Lo))) - f))
        }
    }

    private static let oThreshold: Double = 7.09782712893383973096e+02
    private static let uThreshold: Double = -7.45133219101941108420e+02
    private static let invLn2: Double = 1.44269504088896338700e+00
    private static let p1: Double = 1.66666666666666019037e-01
    private static let p2: Double = -2.77777777770155933842e-03
    private static let p3: Double = 6.61375632143793436117e-05
    private static let p4: Double = -1.65339022054652515390e-06
    private static let p5: Double = 4.13813679705723846039e-08
    private static let twoM1000: Double = 9.33263618503218878990e-302

    /// `Math.exp`.
    public static func exp(_ x0: Double) -> Double {
        var x = x0
        let hx0 = UInt32(bitPattern: hi(x))
        let xsb = Int((hx0 >> 31) & 1)
        let hx = hx0 & 0x7fff_ffff
        if hx >= 0x4086_2E42 {
            if hx >= 0x7ff0_0000 {
                if ((hx & 0xfffff) | lo(x)) != 0 { return x + x }
                return xsb == 0 ? x : 0.0
            }
            if x > oThreshold { return Double.infinity }
            if x < uThreshold { return 0.0 }
        }
        let ln2hi = [ln2Hi, -ln2Hi]
        let ln2lo = [ln2Lo, -ln2Lo]
        let half = [0.5, -0.5]
        var hiV = 0.0
        var loV = 0.0
        var k: Int32 = 0
        if hx > 0x3fd6_2e42 {
            if hx < 0x3FF0_A2B2 {
                hiV = x - ln2hi[xsb]
                loV = ln2lo[xsb]
                k = Int32(1 - xsb - xsb)
            } else {
                k = Int32(truncatingIfNeeded: Int(mad(invLn2, x, half[xsb])))
                let t = Double(k)
                hiV = mad(-t, ln2hi[0], x)
                loV = t * ln2lo[0]
            }
            x = hiV - loV
        } else if hx < 0x3e30_0000 {
            return 1.0 + x
        }
        let t = x * x
        let c = mad(-t, mad(t, mad(t, mad(t, mad(t, p5, p4), p3), p2), p1), x)
        if k == 0 { return 1.0 - ((x * c) / (c - 2.0) - x) }
        var y = 1.0 - ((loV - (x * c) / (2.0 - c)) - hiV)
        if k >= -1021 {
            if k == 1024 { return y * 2.0 * Double(bitPattern: 0x7fe0_0000_0000_0000) }
            y = withHi(y, hi(y) &+ (k << 20))
            return y
        }
        y = withHi(y, hi(y) &+ ((k + 1000) << 20))
        return y * twoM1000
    }

    private static let ivln2Hi: Double = 1.44269504072144627571e+00
    private static let ivln2Lo: Double = 1.67517131648865118353e-10

    private static func kLog1p(_ f: Double) -> Double {
        let s = f / (2.0 + f)
        let z = s * s
        let w = z * z
        let t1 = w * mad(w, mad(w, lg6, lg4), lg2)
        let t2 = z * mad(w, mad(w, mad(w, lg7, lg5), lg3), lg1)
        let r = t2 + t1
        let hfsq = 0.5 * f * f
        return s * (hfsq + r)
    }

    /// `Math.log2`.
    public static func log2(_ x0: Double) -> Double {
        var x = x0
        var hx = hi(x)
        let lx = lo(x)
        var k: Int32 = 0
        if hx < 0x0010_0000 {
            if (UInt32(bitPattern: hx & 0x7fff_ffff) | lx) == 0 { return -Double.infinity }
            if hx < 0 { return Double.nan }
            k -= 54
            x *= two54
            hx = hi(x)
        }
        if hx >= 0x7ff0_0000 { return x + x }
        if hx == 0x3ff0_0000 && lo(x) == 0 { return 0.0 }
        k += (hx >> 20) - 1023
        hx &= 0x000f_ffff
        let i: Int32 = (hx + 0x95f64) & 0x10_0000
        x = withHi(x, hx | (i ^ 0x3ff0_0000))
        k += i >> 20
        let y = Double(k)
        let f = x - 1.0
        let hfsq = 0.5 * f * f
        let r = kLog1p(f)
        let hiV = withLoZero(f - hfsq)
        let loV = (f - hiV) - hfsq + r
        var valHi = hiV * ivln2Hi
        var valLo = mad(loV + hiV, ivln2Lo, loV * ivln2Hi)
        let w = y + valHi
        valLo += (y - w) + valHi
        valHi = w
        return valLo + valHi
    }

    private static let s1: Double = -1.66666666666666324348e-01
    private static let s2: Double = 8.33333333332248946124e-03
    private static let s3: Double = -1.98412698298579493134e-04
    private static let s4: Double = 2.75573137070700676789e-06
    private static let s5: Double = -2.50507602534068634195e-08
    private static let s6: Double = 1.58969099521155010221e-10
    private static let c1: Double = 4.16666666666666019037e-02
    private static let c2: Double = -1.38888888888741095749e-03
    private static let c3: Double = 2.48015872894767294178e-05
    private static let c4: Double = -2.75573143513906633035e-07
    private static let c5: Double = 2.08757232129817482790e-09
    private static let c6: Double = -1.13596475577881948265e-11
    private static let pio2_1: Double = 1.57079632673412561417e+00
    private static let pio2_1t: Double = 6.07710050650619224932e-11
    private static let pio2_2: Double = 6.07710050630396597660e-11
    private static let pio2_2t: Double = 2.02226624879595063154e-21

    private static func kernelSin(_ x: Double, _ y: Double, _ iy: Int) -> Double {
        let ix = hi(x) & 0x7fff_ffff
        if ix < 0x3e40_0000 && Int32(truncatingIfNeeded: Int(x)) == 0 { return x }
        let z = x * x
        let v = z * x
        let r = mad(z, mad(z, mad(z, mad(z, s6, s5), s4), s3), s2)
        if iy == 0 { return mad(v, mad(z, r, s1), x) }
        return x - (mad(-v, s1, mad(z, mad(0.5, y, -(v * r)), -y)))
    }

    private static func kernelCos(_ x: Double, _ y: Double) -> Double {
        let ix = hi(x) & 0x7fff_ffff
        if ix < 0x3e40_0000 && Int32(truncatingIfNeeded: Int(x)) == 0 { return 1.0 }
        let z = x * x
        let r = z * mad(z, mad(z, mad(z, mad(z, mad(z, c6, c5), c4), c3), c2), c1)
        if ix < 0x3FD3_3333 { return 1.0 - mad(0.5, z, -mad(z, r, -(x * y))) }
        let qx: Double = ix > 0x3fe9_0000 ? 0.28125 : withLoZero(withHi(0.0, ix - 0x0020_0000))
        let hz = mad(0.5, z, -qx)
        let a = 1.0 - qx
        return a - (hz - mad(z, r, -(x * y)))
    }

    /// `Math.sin`. Arguments beyond 3 pi / 4 in magnitude use the platform sine (the wallet only takes sin(pi * x) for x < 1/2).
    public static func sin(_ x: Double) -> Double {
        let ix = hi(x) & 0x7fff_ffff
        if ix <= 0x3fe9_21fb { return kernelSin(x, 0.0, 0) }
        if ix >= 0x7ff0_0000 { return x - x }
        if ix < 0x4002_d97c {
            let n: Int
            let y0: Double
            let y1: Double
            if hi(x) > 0 {
                var z = x - pio2_1
                if ix != 0x3ff9_21fb {
                    y0 = z - pio2_1t
                    y1 = (z - y0) - pio2_1t
                } else {
                    z -= pio2_2
                    y0 = z - pio2_2t
                    y1 = (z - y0) - pio2_2t
                }
                n = 1
            } else {
                var z = x + pio2_1
                if ix != 0x3ff9_21fb {
                    y0 = z + pio2_1t
                    y1 = (z - y0) + pio2_1t
                } else {
                    z += pio2_2
                    y0 = z + pio2_2t
                    y1 = (z - y0) + pio2_2t
                }
                n = -1
            }
            switch n & 3 {
            case 0: return kernelSin(y0, y1, 1)
            case 1: return kernelCos(y0, y1)
            case 2: return -kernelSin(y0, y1, 1)
            default: return -kernelCos(y0, y1)
            }
        }
        return Foundation.sin(x)
    }
}
