//! Internal events produced by `pb-monitor` watchers and consumed by the daemon (tokio mpsc channel).
//! Not part of the IPC protocol (the app receives [`crate::ipc::DaemonEvent`] instead).

use crate::model::{DeviceEvent, PersistenceChangeKind, PersistenceItem};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileEventSource {
    FsEvents,
    /// eslogger `create`
    EsCreate,
    /// eslogger `rename` (destination path)
    EsRename,
    /// eslogger `close` with `modified == true`
    EsCloseModified,
}

/// Code-signing facts reported by Endpoint Security for a process (cheap, no `codesign` call needed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EsProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdhash: Option<String>,
    pub is_platform_binary: bool,
    /// ES `codesigning_flags` (CS_VALID = 0x1, CS_ADHOC = 0x2, CS_RUNTIME = 0x10000…).
    pub codesigning_flags: u32,
    pub uid: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MonitorEvent {
    /// A file was created / written / moved into a watched location. The daemon debounces per path
    /// (a file being downloaded produces many events) before scanning.
    FileActivity {
        path: String,
        source: FileEventSource,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        process: Option<EsProcessInfo>,
    },
    /// A process was executed (eslogger `exec`). `target` is the new image.
    ProcessExec {
        target: EsProcessInfo,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent: Option<EsProcessInfo>,
    },
    /// A persistence item appeared / changed / disappeared.
    Persistence {
        item: PersistenceItem,
        change: PersistenceChangeKind,
    },
    /// A device was seen (new / connected / disconnected). Volumes included.
    Device(DeviceEvent),
    /// A watcher started, failed or recovered.
    MonitorHealth {
        monitor: String,
        ok: bool,
        message: String,
    },
}
