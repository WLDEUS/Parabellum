import Foundation

/// Every command of `crates/pb-core/src/ipc.rs` (`Request`), encoded as
/// `{"id":N,"cmd":"<snake_case>",…fields}` — snake_case keys, nil optionals omitted, every other field
/// always present (exactly what serde produces for `RequestEnvelope`).
///
/// The comment of each case names the type of the response `data`.
public enum Request: Sendable, Equatable {
    /// → `PingResponse`
    case ping
    /// → `StatusInfo`
    case status
    /// → `JobStarted`
    case scan(paths: [String], recursive: Bool = true, useClamav: Bool? = nil)
    /// → `null`
    case cancelScan(jobId: String)
    /// → `[ScanJobSummary]`
    case listJobs(limit: Int = 100)
    /// → `ScanJobDetail`
    case getJob(jobId: String)
    /// → `[SecurityAlert]`
    case listAlerts(limit: Int = 100, includeResolved: Bool = false)
    /// → `SecurityAlert` (updated)
    case resolveAlert(alertId: Int64, action: AlertAction)
    /// → `[QuarantineEntry]`
    case listQuarantine
    /// → `QuarantineEntry`
    case quarantinePath(path: String)
    /// → `RestoredPath`
    case restore(entryId: String, allow: Bool = false)
    /// → `null`
    case deleteQuarantined(entryId: String)
    /// → `null`
    case reportFalsePositive(sha256: String, path: String? = nil, note: String? = nil)
    /// → `[PersistenceItem]`
    case listPersistence(onlyNew: Bool = false)
    /// → `PersistenceItem`
    case setPersistenceStatus(itemId: String, status: PersistenceStatus)
    /// → `[DeviceInfo]`
    case listDevices(kind: DeviceKind? = nil)
    /// → `DeviceInfo`
    case setDeviceTrust(deviceId: String, trust: DeviceTrust)
    /// → `JobStarted` (completion pushed as `update_finished`)
    case updateNow(target: UpdateTarget)
    /// → `[ComponentStatus]`
    case listComponents
    /// → `JobStarted`
    case installComponent(name: String)
    /// → `[ComponentStatus]`
    case setComponentAutoUpdate(name: String, autoUpdate: Bool)
    /// → `DnsStatus`
    case getDns
    /// → `DnsStatus`
    case setDns(enabled: Bool)
    /// → `AdblockStatus`
    case adblockStatus
    /// → `Config`
    case getConfig
    /// Replace the whole config. `preserving` is the raw JSON last received from `get_config`: keys this
    /// build does not know are kept (deep merge) so a newer daemon never loses settings. → `Config`
    case setConfig(Config, preserving: JSONValue? = nil)
    /// 0 = resume now. → `StatusInfo`
    case setProtection(pausedMinutes: Int)
    /// 0 = current week. → `WeeklyReport`
    case weeklyReport(weekOffset: Int = 0)
    /// → `JobStarted`
    case retroHunt(days: Int = 30)
    /// Start receiving events on this connection. → `null`
    case subscribe

    /// Wire name (`cmd`).
    public var command: String {
        switch self {
        case .ping: return "ping"
        case .status: return "status"
        case .scan: return "scan"
        case .cancelScan: return "cancel_scan"
        case .listJobs: return "list_jobs"
        case .getJob: return "get_job"
        case .listAlerts: return "list_alerts"
        case .resolveAlert: return "resolve_alert"
        case .listQuarantine: return "list_quarantine"
        case .quarantinePath: return "quarantine_path"
        case .restore: return "restore"
        case .deleteQuarantined: return "delete_quarantined"
        case .reportFalsePositive: return "report_false_positive"
        case .listPersistence: return "list_persistence"
        case .setPersistenceStatus: return "set_persistence_status"
        case .listDevices: return "list_devices"
        case .setDeviceTrust: return "set_device_trust"
        case .updateNow: return "update_now"
        case .listComponents: return "list_components"
        case .installComponent: return "install_component"
        case .setComponentAutoUpdate: return "set_component_auto_update"
        case .getDns: return "get_dns"
        case .setDns: return "set_dns"
        case .adblockStatus: return "adblock_status"
        case .getConfig: return "get_config"
        case .setConfig: return "set_config"
        case .setProtection: return "set_protection"
        case .weeklyReport: return "weekly_report"
        case .retroHunt: return "retro_hunt"
        case .subscribe: return "subscribe"
        }
    }

    /// Same classification as `Request::is_mutating` (the daemon checks the peer for these).
    public var isMutating: Bool {
        switch self {
        case .ping, .status, .listJobs, .getJob, .listAlerts, .listQuarantine, .listPersistence,
             .listDevices, .listComponents, .getDns, .adblockStatus, .getConfig, .weeklyReport, .subscribe:
            return false
        default:
            return true
        }
    }

    /// Same classification as `Request::requires_admin` in Rust: protection-weakening or destructive
    /// commands. The daemon answers `auth_required` unless the envelope carries `auth` (base64 of an
    /// `AuthorizationExternalForm` holding `DaemonProtocol.adminRight`) or the peer is root.
    public var requiresAdmin: Bool {
        switch self {
        case .restore, .deleteQuarantined, .reportFalsePositive, .setConfig, .quarantinePath, .setPersistenceStatus:
            return true
        case let .setDns(enabled):
            return !enabled
        case let .setProtection(pausedMinutes):
            return pausedMinutes > 0
        case let .setDeviceTrust(_, trust):
            return trust != .blocked
        case let .setComponentAutoUpdate(_, autoUpdate):
            return !autoUpdate
        case let .resolveAlert(_, action):
            switch action {
            case .allow, .restore, .trustDevice, .approvePersistence, .removePersistence, .reportFalsePositive:
                return true
            default:
                return false
            }
        default:
            return false
        }
    }

    /// The request envelope as a JSON tree. `auth` (omitted when nil) travels next to `id` / `cmd`.
    public func jsonObject(id: UInt64, auth: String? = nil) throws -> JSONValue {
        var o: [String: JSONValue] = [
            "id": .int(Int64(clamping: id)),
            "cmd": .string(command),
        ]
        if let auth {
            o["auth"] = .string(auth)
        }
        switch self {
        case .ping, .status, .listQuarantine, .listComponents, .getDns, .adblockStatus, .getConfig, .subscribe:
            break
        case let .scan(paths, recursive, useClamav):
            o["paths"] = .array(paths.map { JSONValue.string($0) })
            o["recursive"] = .bool(recursive)
            if let useClamav {
                o["use_clamav"] = .bool(useClamav)
            }
        case let .cancelScan(jobId):
            o["job_id"] = .string(jobId)
        case let .listJobs(limit):
            o["limit"] = .int(Int64(limit))
        case let .getJob(jobId):
            o["job_id"] = .string(jobId)
        case let .listAlerts(limit, includeResolved):
            o["limit"] = .int(Int64(limit))
            o["include_resolved"] = .bool(includeResolved)
        case let .resolveAlert(alertId, action):
            o["alert_id"] = .int(alertId)
            o["action"] = .string(action.rawValue)
        case let .quarantinePath(path):
            o["path"] = .string(path)
        case let .restore(entryId, allow):
            o["entry_id"] = .string(entryId)
            o["allow"] = .bool(allow)
        case let .deleteQuarantined(entryId):
            o["entry_id"] = .string(entryId)
        case let .reportFalsePositive(sha256, path, note):
            o["sha256"] = .string(sha256)
            if let path {
                o["path"] = .string(path)
            }
            if let note {
                o["note"] = .string(note)
            }
        case let .listPersistence(onlyNew):
            o["only_new"] = .bool(onlyNew)
        case let .setPersistenceStatus(itemId, status):
            o["item_id"] = .string(itemId)
            o["status"] = .string(status.rawValue)
        case let .listDevices(kind):
            if let kind {
                o["kind"] = .string(kind.rawValue)
            }
        case let .setDeviceTrust(deviceId, trust):
            o["device_id"] = .string(deviceId)
            o["trust"] = .string(trust.rawValue)
        case let .updateNow(target):
            o["target"] = .string(target.rawValue)
        case let .installComponent(name):
            o["name"] = .string(name)
        case let .setComponentAutoUpdate(name, autoUpdate):
            o["name"] = .string(name)
            o["auto_update"] = .bool(autoUpdate)
        case let .setDns(enabled):
            o["enabled"] = .bool(enabled)
        case let .setConfig(config, preserving):
            let known = try JSONValue(encoding: config)
            if let preserving {
                o["config"] = preserving.merging(known)
            } else {
                o["config"] = known
            }
        case let .setProtection(pausedMinutes):
            o["paused_minutes"] = .int(Int64(pausedMinutes))
        case let .weeklyReport(weekOffset):
            o["week_offset"] = .int(Int64(weekOffset))
        case let .retroHunt(days):
            o["days"] = .int(Int64(days))
        }
        return .object(o)
    }

    /// One JSON object, without the trailing newline.
    public func encode(id: UInt64, auth: String? = nil) throws -> Data {
        let encoder = JSONEncoder()
        // Never `.prettyPrinted`: the protocol is one object per line.
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(jsonObject(id: id, auth: auth))
    }

    /// One `\n`-terminated JSON line, ready to be written to the socket.
    public func encodeLine(id: UInt64, auth: String? = nil) throws -> Data {
        var data = try encode(id: id, auth: auth)
        data.append(0x0A)
        return data
    }
}
