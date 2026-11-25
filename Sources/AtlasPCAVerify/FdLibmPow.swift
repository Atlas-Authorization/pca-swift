import Foundation

/// `Math.pow`: fdlibm's __ieee754_pow (e_pow.c), statement for statement with the same constants, plus the reference language's rule that
/// (+-1) ** +-Infinity is NaN. Method: log2(x) to extra precision as w1 + w2, y * log2(x) = n + y' with |y'| <= 0.5, x**y = 2**n * exp(y' * ln2).
/// No fused multiply-add is used here. Lanes whose platform pow may round differently from the reference use this routine as the model.
public extension FdLibm {
    @inline(__always) private static func hiP(_ x: Double) -> Int32 { Int32(truncatingIfNeeded: x.bitPattern >> 32) }
    @inline(__always) private static func loP(_ x: Double) -> Int32 { Int32(truncatingIfNeeded: x.bitPattern) }
    @inline(__always) private static func setHi(_ x: Double, _ h: Int32) -> Double {
        Double(bitPattern: (UInt64(UInt32(bitPattern: h)) << 32) | (x.bitPattern & 0xffff_ffff))
    }
    @inline(__always) private static func lo0(_ x: Double) -> Double { Double(bitPattern: x.bitPattern & 0xffff_ffff_0000_0000) }

    static func pow(_ x: Double, _ y: Double) -> Double {
        let signifBits: Int32 = 0x7fffffff
        var z: Double
        var r: Double, t: Double, u: Double, v: Double, w: Double
        var i: Int32, j: Int32, k: Int32, n: Int32

        // y == zero: x**0 = 1
        if y == 0.0 { return 1.0 }
        // NaN propagates
        if x.isNaN || y.isNaN { return x + y }

        let yAbs = abs(y)
        var xAbs = abs(x)
        // special values of y
        if y == 2.0 {
            return x * x
        } else if y == 0.5 {
            if x >= -Double.greatestFiniteMagnitude { return (x + 0.0).squareRoot() } // x == -infinity is handled later; + 0.0 for x == -0.0
        } else if yAbs == 1.0 {
            return y == 1.0 ? x : 1.0 / x
        } else if yAbs == Double.infinity {
            if xAbs == 1.0 {
                return y - y // (+-1)**+-inf is NaN
            } else if xAbs > 1.0 {
                return y >= 0 ? y : 0.0 // (|x| > 1)**+-inf = inf, 0
            } else {
                return y < 0 ? -y : 0.0 // (|x| < 1)**-+inf = inf, 0
            }
        }

        let hx = hiP(x)
        var ix = hx & signifBits

        // yIsInt = 0: y is not an integer, 1: y is an odd integer, 2: y is an even integer (only needed for x < 0)
        var yIsInt: Int32 = 0
        if hx < 0 {
            if yAbs >= 0x1.0p53 {
                yIsInt = 2 // even: ulp(2^53) = 2
            } else if yAbs >= 1.0 {
                let yAbsAsLong = Int64(yAbs)
                if Double(yAbsAsLong) == yAbs { yIsInt = 2 - Int32(yAbsAsLong & 1) }
            }
        }

        // special values of x
        if xAbs == 0.0 || xAbs == Double.infinity || xAbs == 1.0 {
            z = xAbs // x is +-0, +-inf, +-1
            if y < 0.0 { z = 1.0 / z }
            if hx < 0 {
                if ((ix &- 0x3ff00000) | yIsInt) == 0 {
                    z = (z - z) / (z - z) // (-1)**non-int is NaN
                } else if yIsInt == 1 {
                    z = -1.0 * z // (x < 0)**odd = -(|x|**odd)
                }
            }
            return z
        }

        n = (hx >> 31) &+ 1
        // (x < 0)**(non-int) is NaN
        if (n | yIsInt) == 0 { return (x - x) / (x - x) }

        var s = 1.0 // sign of the result: -1 for (negative)**(odd integer)
        if (n | (yIsInt &- 1)) == 0 { s = -1.0 }

        var pH: Double, pL: Double, t1: Double, t2: Double
        // |y| is huge
        if yAbs > 0x1.00000ffffffffp31 { // |y| > ~2**31
            let invLn2 = 0x1.71547652b82fep0     // 1.44269504088896338700e+00 = 1/ln2
            let invLn2H = 0x1.71547p+0           // 1.4426946640014648438 = 21 bits of 1/ln2
            let invLn2L = 0x1.94ae0bf85ddf4p-22  // 3.7688749856360991145e-07 = 1/ln2 tail
            // over/underflow if x is not close to one
            if xAbs < 0x1.fffff00000000p-1 { return y < 0.0 ? s * Double.infinity : s * 0.0 }
            if xAbs > 0x1.00000ffffffffp0 { return y > 0.0 ? s * Double.infinity : s * 0.0 }
            // now |1 - x| is tiny <= 2**-20: log(x) by x - x^2/2 + x^3/3 - x^4/4
            t = xAbs - 1.0 // t has 20 trailing zeros
            w = (t * t) * (0.5 - t * (0.3333333333333333333333 - t * 0.25))
            u = invLn2H * t // invLn2H has 21 significant bits
            v = t * invLn2L - w * invLn2
            t1 = u + v
            t1 = lo0(t1)
            t2 = v - (t1 - u)
        } else {
            let cp = 0x1.ec709dc3a03fdp-1    //  9.61796693925975554329e-01 = 2/(3 ln2)
            let cpH = 0x1.ec709ep-1          //  9.61796700954437255859e-01 = (float)cp
            let cpL = -0x1.e2fe0145b01f5p-28 // -7.02846165095275826516e-09 = tail of cpH
            var zH: Double, zL: Double, ss: Double, s2: Double, sH: Double, sL: Double, tH: Double, tL: Double
            n = 0
            // subnormal x
            if ix < 0x00100000 {
                xAbs *= 0x1.0p53
                n &-= 53
                ix = hiP(xAbs)
            }
            n &+= (ix >> 20) &- 0x3ff
            j = ix & 0x000fffff
            // determine the interval
            ix = j | 0x3ff00000 // normalize ix
            if j <= 0x3988E {
                k = 0 // |x| < sqrt(3/2)
            } else if j < 0xBB67A {
                k = 1 // |x| < sqrt(3)
            } else {
                k = 0
                n &+= 1
                ix &-= 0x00100000
            }
            xAbs = setHi(xAbs, ix)

            // ss = sH + sL = (x - 1)/(x + 1) or (x - 1.5)/(x + 1.5)
            let dpH = 0x1.2b8034p-1           // 5.84962487220764160156e-01
            let dpL = 0x1.cfdeb43cfd006p-27   // 1.35003920212974897128e-08
            // polynomial coefficients for (3/2)*(log(x) - 2s - 2/3*s**3)
            let l1 = 0x1.3333333333303p-1     // 5.99999999999994648725e-01
            let l2 = 0x1.b6db6db6fabffp-2     // 4.28571428578550184252e-01
            let l3 = 0x1.55555518f264dp-2     // 3.33333329818377432918e-01
            let l4 = 0x1.17460a91d4101p-2     // 2.72728123808534006489e-01
            let l5 = 0x1.d864a93c9db65p-3     // 2.30660745775561754067e-01
            let l6 = 0x1.a7e284a454eefp-3     // 2.06975017800338417784e-01
            let kD = Double(k)
            let bpK = 1.0 + 0.5 * kD // BP[0] = 1.0, BP[1] = 1.5
            u = xAbs - bpK
            v = 1.0 / (xAbs + bpK)
            ss = u * v
            sH = ss
            sH = lo0(sH)
            // tH = xAbs + BP[k], high part
            tH = 0.0
            tH = setHi(tH, ((ix >> 1) | 0x20000000) &+ 0x00080000 &+ (k << 18))
            tL = xAbs - (tH - bpK)
            sL = v * ((u - sH * tH) - sH * tL)
            // log(xAbs)
            s2 = ss * ss
            r = s2 * s2 * (l1 + s2 * (l2 + s2 * (l3 + s2 * (l4 + s2 * (l5 + s2 * l6)))))
            r += sL * (sH + ss)
            s2 = sH * sH
            tH = 3.0 + s2 + r
            tH = lo0(tH)
            tL = r - ((tH - 3.0) - s2)
            // u + v = ss * (1 + ...)
            u = sH * tH
            v = sL * tH + tL * ss
            // 2/(3 log2) * (ss + ...)
            pH = u + v
            pH = lo0(pH)
            pL = v - (pH - u)
            zH = cpH * pH // cpH + cpL = 2/(3 log2)
            zL = cpL * pH + pL * cp + dpL * kD
            // log2(xAbs) = (ss + ...) * 2/(3 log2) = n + dpH + zH + zL
            t = Double(n)
            t1 = (((zH + zL) + dpH * kD) + t)
            t1 = lo0(t1)
            t2 = zL - (((t1 - t) - dpH * kD) - zH)
        }

        // split y into y1 + y2 and compute (y1 + y2) * (t1 + t2)
        var y1 = y
        y1 = lo0(y1)
        pL = (y - y1) * t1 + y * t2
        pH = y1 * t1
        z = pL + pH
        j = hiP(z)
        i = loP(z)
        if j >= 0x40900000 { // z >= 1024
            if ((j &- 0x40900000) | i) != 0 { // z > 1024
                return s * Double.infinity // overflow
            } else {
                let ovt = 8.0085662595372944372e-0017 // -(1024 - log2(ovfl + .5ulp))
                if pL + ovt > z - pH { return s * Double.infinity } // overflow
            }
        } else if (j & signifBits) >= 0x4090cc00 { // z <= -1075
            if ((j &- Int32(bitPattern: 0xc090cc00)) | i) != 0 { // z < -1075
                return s * 0.0 // underflow
            } else {
                if pL <= z - pH { return s * 0.0 } // underflow
            }
        }

        // 2**(pH + pL)
        let p1 = 0x1.555555555553ep-3     //  1.66666666666666019037e-01
        let p2 = -0x1.6c16c16bebd93p-9    // -2.77777777770155933842e-03
        let p3 = 0x1.1566aaf25de2cp-14    //  6.61375632143793436117e-05
        let p4 = -0x1.bbd41c5d26bf1p-20   // -1.65339022054652515390e-06
        let p5 = 0x1.6376972bea4d0p-25    //  4.13813679705723846039e-08
        let lg2 = 0x1.62e42fefa39efp-1    //  6.93147180559945286227e-01
        let lg2H = 0x1.62e43p-1           //  6.93147182464599609375e-01
        let lg2L = -0x1.05c610ca86c39p-29 // -1.90465429995776804525e-09
        i = j & signifBits
        k = (i >> 20) &- 0x3ff
        n = 0
        if i > 0x3fe00000 { // |z| > 0.5: n = [z + 0.5]
            n = j &+ (0x00100000 >> (k &+ 1))
            k = ((n & signifBits) >> 20) &- 0x3ff // new k for n
            t = 0.0
            t = setHi(t, n & ~(0x000fffff >> k))
            n = ((n & 0x000fffff) | 0x00100000) >> (20 &- k)
            if j < 0 { n = -n }
            pH -= t
        }
        t = pL + pH
        t = lo0(t)
        u = t * lg2H
        v = (pL - (t - pH)) * lg2 + t * lg2L
        z = u + v
        w = v - (z - u)
        t = z * z
        t1 = z - t * (p1 + t * (p2 + t * (p3 + t * (p4 + t * p5))))
        r = (z * t1) / (t1 - 2.0) - (w + z * w)
        z = 1.0 - (r - z)
        j = hiP(z)
        j &+= (n << 20)
        if (j >> 20) <= 0 {
            z = scalbn(z, Int(n)) // subnormal output
        } else {
            z = setHi(z, hiP(z) &+ (n << 20))
        }
        return s * z
    }
}
