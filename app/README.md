# Parabellum.app (SwiftUI)

Menu bar app + main window for `parabellumd`. SwiftPM package, no `.xcodeproj`. macOS 14+, arm64.

| Target | Type | Contents |
|---|---|---|
| `ParabellumKit` | library (Foundation + CryptoKit) | Models mirroring `pb-core` (`Models.swift`, `ProtectionModels.swift`, `Config.swift`, `ProtectionConfig.swift`), `Request` encoding, `DaemonClient` (Unix socket, JSON lines), French labels and formatting, local tools (`LocalTools.swift`: Pwned Passwords range API, CLI runner for metadata cleaning / password exports) |
| `Parabellum` | executable (SwiftUI + AppKit + UserNotifications + Charts) | `@main` app, `AppModel`, notifications, BadUSB panel, one view per file in `Views/` |
| `ParabellumKitTests` | XCTest | Decodes the fixtures emitted by the Rust types, checks request encoding, runs the client against a local fake daemon |

The app target has **no SwiftPM resources** (SF Symbols only), so no `.bundle` needs copying into `Contents/Resources`. Only the test target has resources (`Tests/ParabellumKitTests/Fixtures`).

## Build

```sh
cd app
swift build -c release --arch arm64
# binary: .build/arm64-apple-macosx/release/Parabellum (also reachable via `swift build --show-bin-path`)
swift test
```

`installer/` wraps the binary into `Parabellum.app` (`Contents/MacOS/Parabellum`, Info.plist with `LSUIElement=YES`, bundle id `com.wldeus.parabellum`) and signs it ad hoc.

## Run against a dev daemon

The app talks to `/var/run/parabellum.sock` unless `PARABELLUM_SOCKET` is set:

```sh
# daemon relocated under a temporary root (socket at $ROOT/run/parabellum.sock)
PARABELLUM_ROOT=/tmp/pb cargo run -p pb-daemon
# app (outside a .app bundle: no notifications, see below)
PARABELLUM_SOCKET=/tmp/pb/run/parabellum.sock swift run Parabellum
```

Limits of a `swift run` build:
- **Notifications are disabled** (`UNUserNotificationCenter` requires an `.app` bundle); everything else works.
- The daemon only accepts **mutating** commands (scan, quarantine, set_config…) from the installed app/CLI: from a dev build you get `permission_denied` for those, even with administrator approval. Read-only screens work.

## Administrator approval

Protection-weakening or destructive commands (`Request.requiresAdmin`, mirror of `Request::requires_admin`:
restore / delete / quarantine a file, false positive, `set_config`, persistence changes, disabling DNS, pausing
protection, trusting a device, disabling a component's auto-update, alert actions that allow / restore / trust /
approve / remove) carry `auth`: the base64 `AuthorizationExternalForm` of an authorization holding
`com.wldeus.parabellum.admin`, obtained with the system password / Touch ID prompt (`AdminAuthorizer`).
The authorization is reused for 5 minutes (the daemon re-checks it every time); an `auth_required` answer is
retried once with a fresh one; cancelling the prompt sends nothing. `get_config` returns secrets as
`********` unless `auth` is supplied: Réglages shows them as "définie" with a "Modifier…" button that asks
for approval; sending `********` back keeps the stored secret.

## Regenerating the fixtures

When `crates/pb-core` changes:

```sh
cargo run -p pb-core --example gen_fixtures -- app/Tests/ParabellumKitTests/Fixtures
cd app && swift test
```

## Behaviour notes

- One request connection (correlated by `id`, 30 s timeout) and one event connection (`subscribe`), reconnected with backoff 1 s → 30 s. The only timer is a 60 s status refresh.
- Unknown enum values / event names from a newer daemon decode to `unknown` (never a crash); `set_config` merges the edited config over the raw JSON from `get_config`, so unknown keys survive.
- The new-keyboard panel never becomes key (mouse-only answer, so a BadUSB device cannot "type" the answer).
- Daemon down: `sudo launchctl kickstart -k system/com.wldeus.parabellum.daemon`.
