# TrustRemediation

**Your third-party SDKs ship their own trust store, and an OS update can't fix it.** This package is the remediation system an iOS lead wishes they had already built before a CA compromise: a signed, rollback-proof security manifest that switches off exposed network paths in builds already in the field, stages a forced upgrade against a clock the user can't wind back, measures how much of the fleet is still exposed, and fails CI before the next release ships the same bad dependency.

**Demo app:** [trust-incident-remediation-demo-app](https://github.com/rajatslakhina/trust-incident-remediation-demo-app), a SwiftUI console that runs a whole incident against this library through a version-pinned remote package dependency.

---

## Why this matters

In October 2026 the private keys of eight eMudhra intermediate CAs leaked. Apple distrusted the certificates, then the root, at the OS level. That protects every `URLSession` call that uses the system trust store, and nothing else. SDKs that bundle their own root list (gRPC/BoringSSL stacks, some sync and analytics SDKs) kept trusting the compromised CA until each vendor shipped a fixed SDK, each app shipped a new binary with it, and each user installed that binary. Firestore needed 13.1.1 / 12.19.3.

For the weeks that takes, the only lever an app team has over binaries already on phones is configuration they shipped earlier. Most apps have remote config. Very few have remote config that is safe to rely on during a TLS incident, where the transport carrying the config may itself be the thing that is compromised. That gap is what this package closes, and every design decision below follows from the assumption that **the network is hostile**.

## What's in it

```
TrustRemediation (platform-agnostic core, tested on Linux + macOS)
├── ManifestVerifier        Ed25519 over exact payload bytes · pinned key set (rotation) · structural limits
├── ManifestLedger          anti-rollback floor · compiled-in TrustFloor · equivocation → union of restrictions · never-overwrite-unreadable
├── TrustedTimeline         signed-time anchor + monotonic uptime · persisted high-water floor
├── CapabilityGate          catalog × build × manifest → full / degraded / disabled, order-independent
├── UpgradeRequirement      staged soft → hard enforcement against trusted time
├── RemediationCoordinator  actor · single-flight refresh · atomic check-and-commit
├── ExposureAnalyzer        % of installed base still exposed · k-anonymous buckets · trap-free maths
└── AdvisoryGate            Package.resolved (v1/v2/v3) × advisory feed → CI verdict, fails closed
TrustRemediationUI
├── RemediationLab          deterministic incident script: signing server, hostile network, clock, fleet
└── RemediationConsoleView  SwiftUI console over the lab (iOS 17+)
```

## Design decisions and trade-offs

**1. The manifest can only restrict.** Rules either `degrade` or `disable` a capability the binary already declares. There is no `enable`. A stolen signing key is still serious: it can sign a newer manifest that lifts current restrictions, back to the binary's compiled-in posture. What it can never do is switch on behaviour the binary didn't ship enabled. It also can't freeze the fleet: the ledger refuses version jumps of more than 1,000,000 past the floor, so a manifest at `UInt64.max` can't lock out every later (rotated-key) manifest. It also keeps the system on the right side of App Review Guideline 2.5.19: there is no dormant feature to unlock. *Rejected:* a general-purpose remote-config payload. It is more flexible, but then a signing-key compromise is a remote feature-unlock primitive.

**2. Sign the bytes, not the JSON.** The signature covers the payload exactly as received, and the client decodes only after the signature verifies. *Rejected:* canonical JSON. Foundation makes no canonical-form promise across OS versions, and "verified one encoding, used another" is a classic bug. The cost is that the server must keep the exact bytes it signed, which it should do anyway.

**3. Anti-rollback is a durable floor, a compiled-in floor, and bounded validity.** The ledger persists the highest accepted version and refuses anything lower, including across relaunches. Every manifest also carries a signed validity window, capped at 30 days. A fresh install, or a device whose storage is wiped or unreadable, has no persisted floor. So each release compiles in a `TrustFloor`: its build date, which seeds the trusted-time high-water mark, and optionally the manifest version that was current when it was cut. A replay of last year's validly signed manifest is therefore rejected as expired even on day one. Without the compiled-in floor it would be accepted and would read as fresh; that case was the main finding of this repo's first review round.

**Equivocation** is two different signed payloads at the same version, which points to a compromised or broken signing pipeline. The second copy never replaces the first. Instead, the ledger records the version, persists the extra copy, and from then on enforces the *union* of both copies' restrictions (and the stricter of their upgrade policies). Whichever copy an attacker manages to deliver first, the stricter reading wins, within a bound: up to four extra copies are enforced per version (all are recorded). If no copy is currently applied, because the stored one was dropped at load, the equivocating copy is kept as a restriction. A newer version clears the fork, so equivocation is reported loudly but never becomes a permanent lockout. *Rejected:* first-seen-wins, which lets whoever wins the race pick the weaker policy.

**4. Time comes only from signed evidence.** An HTTP `Date` header travels over the compromised channel, so it isn't evidence of anything. `TrustedTimeline` anchors only to a verified manifest's signed `issuedAt` and adds monotonic uptime on top, so changing the wall clock moves nothing while the timeline is anchored. The anchor lives in memory. After a relaunch or a reboot, the timeline falls back to the wall clock, floored at a persisted high-water mark that only signed-anchored time can raise. Writes of that mark are throttled to once an hour, except that it is written immediately when it crosses a deadline. Separately, once trusted time on any basis passes a hard-enforcement deadline (`requiredFrom`), that deadline is latched to disk. Winding the clock back and relaunching therefore can't undo a hard-upgrade requirement the app has already enforced, even in sessions where no new manifest re-anchored time. The latch is restrict-only: a fast clock can latch a deadline early, and the next applied manifest clears it. *Residual gap:* manifest *staleness* is still judged on floored time. In a session with no new signed anchor, winding the clock back can keep an expired manifest looking fresh. The server is expected to re-issue manifests (with a version bump) on a fixed cadence, as the demo's lab does daily. The high-water mark is raised **only from signed-anchored time**. If it were raised from the wall clock, one accidental jump a year forward would be persisted, and every manifest after that would read as expired: a permanent, self-inflicted lockout. *Trade-off:* expiry at acceptance is checked only against signed evidence (anchored time, else the high-water mark). A phone whose clock is a year fast can still accept the fix that tells it to stop.

**5. Fail-safe direction, per trust path.** Every capability declares its `TrustPath`. A `.systemTrust` path is covered by the OS block, so with no fresh manifest it runs fully. An `.embeddedTrustStore` path isn't covered, so with no fresh manifest it runs degraded. A stale manifest keeps all of its restrictions: time passing never loosens policy. *Trade-off:* on a fresh install with no network, embedded-trust features start degraded until the first manifest arrives. The catalog author can override this per capability.

**6. Hard enforcement turns off network paths; it doesn't brick the app.** `.required` disables only the capabilities marked `blockedWhenUpgradeRequired`. Local data and system-trust features keep working. *Rejected:* a full-screen "update now" wall. It punishes users for the vendor's incident and pushes them toward reinstall loops.

**7. Reentrancy-safe by construction.** `ManifestLedger` is a value type with *synchronous* persistence, so there is no suspension point between "version > floor?" and "floor = version". `RemediationCoordinator`'s only `await` is the network fetch, and everything after it runs in one actor turn. Refreshes are single-flight: when a fleet-wide push wakes every app at once, each device makes one fetch instead of one per trigger.

**8. Storage failure modes are explicit.** If the stored state exists but can't be read (corruption, or iOS file protection before first unlock), the ledger runs in memory and **never writes**. Overwriting state it couldn't read would erase the very floor it exists to protect. Without a readable floor there is also no rollback protection, so in this mode verified manifests are applied **as extra restrictions only** (`.restrictionsOnly`) on top of the compiled-in fallback posture. A replayed old all-clear can't lift anything, and a fresh restricting manifest still takes effect. If writes fail, accepted manifests still apply in memory (`durable: false`). Getting a security fix applied matters more than durability, and the next successful write catches up.

**9. The CI half closes the loop.** The manifest protects builds already shipped. `AdvisoryGate` stops the *next* build from shipping the same bad dependency. It reads `Package.resolved` (v1/v2/v3), matches pins against an advisory feed by SwiftPM identity, and fails closed in two cases: branch or revision pins it can't assess, and advisories with no version ranges, which cover every version. That is the same convention as an empty `affectedBuilds` on a rule. v1 files store the manifest *name* rather than the identity, so the identity is derived from the repository URL; otherwise a v1 file would silently fail open. *Honest scope:* it reads `Package.resolved`, not the SE-0509 SBOM format.

**10. An app update never re-opens a switch.** A new binary may be unable to treat the stored manifest as current. The pinned key may have been rotated out, the limits tightened, the schema bumped, or the compiled-in version floor raised past it. Its *restrictions* are kept anyway, along with those of any stored equivocating copies. They are kept only as restrictions, never as trust, so they can't make anything FULL, and they stay in force until a newer manifest is applied. *Rejected:* dropping them. Then a routine release would silently turn an OFF switch back on, and a hostile network could keep it on by blocking the next fetch. *Trade-off:* retention is restrict-only and not re-verified, so a tampered file could add restrictions. Doing that needs write access to the app container, and at worst it degrades service; it can never loosen policy.

**11. Exposure is measured, not guessed.** `ExposureAnalyzer` turns cohort counts into "x% of active installs are still exposed". That number is what should move a lead from *recommended* to *required*. Builds under k installs are merged into one bucket with exposure withheld. *Known limitation:* the fleet totals stay exact, because the decision needs them, so the k-anonymity applies to the per-build breakdown only.

### Rejected alternatives, briefly

| Alternative | Why not |
|---|---|
| Certificate pinning in every SDK | You don't control third-party TLS stacks; that's the whole problem. |
| Server-side kill switch only | The server can't stop an SDK in a shipped binary from talking to *its vendor's* endpoint. |
| Trusting the HTTP `Date` header for expiry | It arrives over the channel the incident compromised. |
| Last-writer-wins remote config | Replays and equivocation become silent policy changes. |
| Hand-rolled Ed25519 | `swift-crypto` re-exports CryptoKit on Apple and runs the same code on Linux, so the Linux CI job exercises real signatures. |

## Usage

```swift
.package(url: "https://github.com/rajatslakhina/trust-incident-remediation-kit.git", from: "1.0.0")
```

```swift
import TrustRemediation

let catalog = CapabilityCatalog([
    CapabilityDescriptor(id: "partnerSync", displayName: "Partner sync", trustPath: .embeddedTrustStore),
    CapabilityDescriptor(id: "photoBackup", displayName: "Photo backup", trustPath: .systemTrust),
])!  // Demo only: the ids above are distinct, so this can't be nil. Handle nil in app code.

let coordinator = RemediationCoordinator(
    catalog: catalog,
    build: BuildVersion("4.1.0")!,  // Demo only: a literal valid version.
    verifier: ManifestVerifier(trustedKeys: pinnedKeys),
    persistence: FileLedgerPersistence(url: applicationSupport.appendingPathComponent("trust-ledger.json")),
    transport: MyManifestTransport(),
    floor: TrustFloor(earliestTrustedTime: buildDate, minimumManifestVersion: 41))

_ = await coordinator.refresh()
let snapshot = await coordinator.snapshot()
if snapshot.decision(for: "partnerSync")?.state == .full { startPartnerSync() }
```

### The CI gate

Run it as an ordinary test in the app's repo, so a bad pin fails the pipeline:

```swift
import TrustRemediation
import XCTest

final class DependencyAdvisoryTests: XCTestCase {
    func testNoResolvedDependencyIsUnderAnOpenAdvisory() throws {
        let resolved = try Data(contentsOf: URL(fileURLWithPath: "MyApp.xcworkspace/xcshareddata/swiftpm/Package.resolved"))
        let advisories = try JSONDecoder().decode([PackageAdvisory].self, from: Data(contentsOf: URL(fileURLWithPath: "advisories.json")))
        let verdict = AdvisoryGate.evaluate(pins: try PackageResolvedParser.parse(resolved),
                                            advisories: advisories, failAt: .high)
        XCTAssertTrue(verdict.passed, "\(verdict.failingFindings)")
    }
}
```

## Running the tests

```sh
swift build -Xswiftc -warnings-as-errors
swift test
```

`swift-crypto` builds BoringSSL on Linux, so the first build takes a minute or two.

## Verification

What was actually verified, and where:

- **Linux (Swift 6.0.3, x86_64), clean build.** After `rm -rf .build`, `swift build -Xswiftc -warnings-as-errors` gives 0 warnings. `swift test` passes **87/87 tests**, stable over 5 consecutive runs.
- **Property checks against broken implementations.** `MutationTests.swift` has reusable checks for five properties: order independence, anti-rollback, the wall-clock floor, single-flight, and stricter-copy-wins on equivocation. Each check is shown to *fail* against a deliberately broken implementation.
- **Hand-applied mutations of the real source.** Each of the 19 mutations below was applied, the suite was run, and the change was reverted. The count is distinct failing **test cases**, not assertions. Every mutation was caught.

| Mutation to the real source | Failing test cases |
|---|---|
| Remove the rollback floor check | 5 |
| Remove the high-water floor from unanchored time | 2 |
| Remove single-flight joining | 2 |
| Accept a same-version fork as a normal update | 8 |
| Raise the high-water mark from wall-clock time | 1 |
| Make rule resolution order-dependent | 3 |
| Let a stale manifest loosen embedded paths | 1 |
| Let unreadable storage be overwritten | 2 |
| Judge expiry by the unanchored wall clock | 1 |
| Ignore the compiled-in time floor | 1 |
| Drop equivocating copies' restrictions | 3 |
| Drop restrictions carried over from storage | 5 |
| Use the v1 `package` name as identity | 1 |
| Throttle the high-water write even across a deadline | 1 |
| Remove the lab's action serialization | 1 |
| Remove the version-jump cap | 1 |
| Let unreadable storage apply manifests as current | 2 |
| Ignore latched deadlines | 1 |
| Don't persist retained restrictions | 1 |

- **Only ever built on Linux.** No part of this package has been built on an Apple platform yet. That includes the CryptoKit path behind `swift-crypto`, the iOS file-protection branch in `FileLedgerPersistence`, and `RemediationConsoleView.swift` (SwiftUI and Observation). The `#if canImport(SwiftUI)` guard keeps the view out of the Linux build, and this machine has no Xcode. Everything it prints goes through `ConsoleText`, which sits outside that guard and is tested on Linux. The `apple` CI job is what will build the SwiftUI layer for the iOS Simulator.
- **CI:** see the Actions tab. Until a run appears there, no CI result is claimed.
- **Simulator run:** none. See the demo repo.

## License

MIT
