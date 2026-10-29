import Foundation

/// A monotonic clock that does not move when the user changes the wall clock.
/// Resets on reboot, which `TrustedTimeline` detects.
public protocol UptimeSource: Sendable {
    func uptime() -> TimeInterval
}

public protocol WallClock: Sendable {
    func now() -> Date
}

public struct SystemUptime: UptimeSource {
    public init() {}
    public func uptime() -> TimeInterval { ProcessInfo.processInfo.systemUptime }
}

public struct SystemWallClock: WallClock {
    public init() {}
    public func now() -> Date { Date() }
}

/// Where the current trusted time came from.
public enum TimeBasis: Equatable, Sendable {
    /// Signed manifest time plus monotonic uptime elapsed since it was accepted.
    case signedAnchor
    /// No anchor this boot: the wall clock, floored at the highest time ever trusted.
    case flooredWallClock
}

/// Trusted time for expiry and enforcement deadlines.
///
/// The threat model for a trust incident includes a network attacker holding a
/// mis-issued certificate, so an HTTP `Date` header is not evidence of anything. The
/// only time this type anchors to is a *verified manifest's signed `issuedAt`*, and
/// elapsed time after that comes from monotonic uptime, which the wall clock can't
/// move.
///
/// Without an anchor this boot (fresh launch, or after a reboot reset uptime) it falls
/// back to the wall clock, floored at a persisted high-water mark. Winding the clock
/// back can therefore never rewind past the latest moment the app already trusted, so
/// it can't dodge a hard-upgrade deadline it had already seen pass. Winding it forward
/// can only make manifests look stale and deadlines arrive early: both restrict, which
/// is the fail-safe direction.
///
/// The high-water mark is only ever raised from *signed-anchored* time. If it were
/// raised from the wall clock, one accidental jump a year forward would be persisted
/// as a floor and keep every future manifest "expired" after the user fixed the clock:
/// a self-inflicted, permanent fail-closed state.
public struct TrustedTimeline: Sendable, Equatable {
    struct Anchor: Sendable, Equatable {
        let signedDate: Date
        let uptimeAtAnchor: TimeInterval
    }

    private(set) var anchor: Anchor?
    public private(set) var highWater: Date?

    public init(highWater: Date? = nil) {
        self.highWater = highWater
    }

    public func now(uptime: TimeInterval, wallClock: Date) -> (date: Date, basis: TimeBasis) {
        if let anchor, uptime >= anchor.uptimeAtAnchor {
            let elapsed = uptime - anchor.uptimeAtAnchor
            if elapsed.isFinite {
                return (maxDate(anchor.signedDate.addingTimeInterval(elapsed), highWater), .signedAnchor)
            }
        }
        // Uptime went backwards (reboot) or there is no anchor yet.
        return (maxDate(wallClock, highWater), .flooredWallClock)
    }

    public var isAnchored: Bool { anchor != nil }

    /// Anchors to a verified manifest's signed time. Forward-only: an older signed
    /// time (a legitimate but late-arriving manifest) never drags trusted time back.
    mutating func anchor(toSigned date: Date, uptime: TimeInterval, wallClock: Date) {
        let current = now(uptime: uptime, wallClock: wallClock)
        if anchor == nil || current.basis != .signedAnchor || date > current.date {
            // With no anchor this boot, the signed time is better evidence than the
            // wall clock even if it is earlier, but never earlier than the high-water.
            anchor = Anchor(signedDate: maxDate(date, highWater), uptimeAtAnchor: uptime)
        }
        advanceHighWater(uptime: uptime, wallClock: wallClock)
    }

    /// Raises the high-water mark to the current time, but only when that time is
    /// signed-anchored. Returns `true` when the mark advanced.
    @discardableResult
    mutating func advanceHighWater(uptime: TimeInterval, wallClock: Date) -> Bool {
        let current = now(uptime: uptime, wallClock: wallClock)
        guard current.basis == .signedAnchor else { return false }
        return raiseHighWater(to: current.date)
    }

    @discardableResult
    private mutating func raiseHighWater(to date: Date) -> Bool {
        guard date.timeIntervalSinceReferenceDate.isFinite else { return false }
        if let highWater, highWater >= date { return false }
        highWater = date
        return true
    }

    private func maxDate(_ a: Date, _ b: Date?) -> Date {
        guard let b else { return a }
        return max(a, b)
    }
}
