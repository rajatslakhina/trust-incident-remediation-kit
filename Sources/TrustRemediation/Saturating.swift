import Foundation

/// Trap-free integer helpers.
///
/// Every arithmetic path reachable from the public API goes through these instead of
/// `+`, `*`, `/` or `Int(Double)`, which trap on overflow, division by zero, NaN or
/// out-of-range input. Ceilings are derived from `Int.max`, never a hard-coded
/// 64-bit literal, so the same code is correct where `Int` is 32 bits wide.
enum Saturating {
    static func add(_ a: Int, _ b: Int) -> Int {
        let (result, overflow) = a.addingReportingOverflow(b)
        guard overflow else { return result }
        return b > 0 ? Int.max : Int.min
    }

    static func multiply(_ a: Int, _ b: Int) -> Int {
        let (result, overflow) = a.multipliedReportingOverflow(by: b)
        guard overflow else { return result }
        return (a < 0) == (b < 0) ? Int.max : Int.min
    }

    /// `nil` for a zero divisor; `Int.min / -1` saturates to `Int.max`.
    static func divide(_ a: Int, _ b: Int) -> Int? {
        guard b != 0 else { return nil }
        let (result, overflow) = a.dividedReportingOverflow(by: b)
        return overflow ? Int.max : result
    }

    /// `nil` for NaN, infinity, or anything outside `Int`'s range.
    static func int(_ value: Double) -> Int? {
        guard value.isFinite else { return nil }
        // Double(Int.max) rounds *up* to 2^(bitWidth-1), which is out of range,
        // so the upper bound must be exclusive.
        guard value >= Double(Int.min), value < Double(Int.max) else { return nil }
        return Int(value)
    }

    /// `part / whole` in basis points (0...10_000), computed at full width so the
    /// intermediate `part * 10_000` can never overflow. `nil` when `whole <= 0`.
    static func basisPoints(_ part: Int, of whole: Int) -> Int? {
        guard whole > 0 else { return nil }
        let clampedPart = min(max(part, 0), whole)
        let wide = clampedPart.multipliedFullWidth(by: 10_000)
        // Quotient <= 10_000 because clampedPart <= whole, so this cannot overflow.
        let (quotient, _) = whole.dividingFullWidth(wide)
        return quotient
    }
}
