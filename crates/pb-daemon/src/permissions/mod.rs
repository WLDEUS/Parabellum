//! Permissions audit (work in progress).

use crate::ctx::Ctx;
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::PermissionsReport;
use std::sync::Arc;

pub async fn get(_ctx: &Arc<Ctx>, _refresh: bool) -> Result<PermissionsReport, IpcError> {
    Err(IpcError::new(
        ErrorCode::Unavailable,
        "audit des permissions indisponible",
    ))
}
