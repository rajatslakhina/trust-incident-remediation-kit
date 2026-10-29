import Foundation

/// Active installs on one build, as aggregated server-side from coarse pings.
public struct InstallCohort: Sendable, Equatable {
    public let build: BuildVersion
    public let activeInstalls: Int

    public init(build: BuildVersion, activeInstalls: Int) {
        self.build = build
        self.activeInstalls = activeInstalls
    }
}

/// "How much of the installed base is still exposed?" — the number that decides when
/// to move from a recommended to a required upgrade.
public struct ExposureReport: Sendable, Equatable {
    public struct Bucket: Sendable, Equatable {
        /// A build string, or `nil` for the merged small-cohort bucket.
        public let build: BuildVersion?
        public let activeInstalls: Int
        public let exposed: Bool?
    }

    public let totalActive: Int
    public let exposedActive: Int
    /// 0...10_000. `nil` when there are no active installs (no denominator).
    public let exposedBasisPoints: Int?
    /// Cohorts at or above the k-anonymity threshold, largest first.
    public let buckets: [Bucket]
    /// How many builds were folded into the "other" bucket.
    public let suppressedCohorts: Int
}

public enum ExposureAnalyzer {
    /// - Parameters:
    ///   - minimumCohortSize: k for k-anonymity. Builds with fewer installs are merged
    ///     into one bucket so a dashboard can't single out a tiny cohort (an internal
    ///     build, one enterprise customer). Values below 1 are treated as 1.
    public static func report(cohorts: [InstallCohort], vulnerable: [VersionRange],
                              minimumCohortSize: Int) -> ExposureReport {
        let k = max(minimumCohortSize, 1)
        // Merge duplicate builds; negative counts are bad input and count as zero.
        var perBuild: [BuildVersion: Int] = [:]
        for cohort in cohorts {
            perBuild[cohort.build] = Saturating.add(perBuild[cohort.build] ?? 0, max(cohort.activeInstalls, 0))
        }

        var total = 0
        var exposedTotal = 0
        var large: [(build: BuildVersion, count: Int, exposed: Bool)] = []
        var otherCount = 0
        var suppressed = 0
        for (build, count) in perBuild {
            let isExposed = vulnerable.contains { $0.contains(build) }
            total = Saturating.add(total, count)
            if isExposed { exposedTotal = Saturating.add(exposedTotal, count) }
            if count >= k {
                large.append((build, count, isExposed))
            } else if count > 0 {
                otherCount = Saturating.add(otherCount, count)
                suppressed = Saturating.add(suppressed, 1)
            }
        }
        // Largest first; newest build first on equal counts, so the order is
        // deterministic (dictionary iteration order is not).
        large.sort { lhs, rhs in
            lhs.count != rhs.count ? lhs.count > rhs.count : lhs.build > rhs.build
        }
        var visible = large.map {
            ExposureReport.Bucket(build: $0.build, activeInstalls: $0.count, exposed: $0.exposed)
        }
        if otherCount > 0 {
            // Exposure of the merged bucket is withheld: reporting it would leak the
            // exposure of any single build in it.
            visible.append(.init(build: nil, activeInstalls: otherCount, exposed: nil))
        }
        return ExposureReport(
            totalActive: total, exposedActive: exposedTotal,
            exposedBasisPoints: Saturating.basisPoints(exposedTotal, of: total),
            buckets: visible, suppressedCohorts: suppressed)
    }
}
