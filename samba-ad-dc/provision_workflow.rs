// ==============================================================================
// Astral AD & Hybrid DNS - Provisioning Workflow Coordinator (Rust)
// ==============================================================================

use std::path::Path;
use serde_json::Value;

use crate::provision_dc1::{execute_dc1_provision, ProvisionRequest};

pub fn execute_workflow(request_val: &Value, root: &Path) -> Result<Value, String> {
    let req: ProvisionRequest = serde_json::from_value(request_val.clone())
        .map_err(|e| format!("Formato inválido de requisição de provisionamento: {}", e))?;

    let res = execute_dc1_provision(&req, root)?;
    let val = serde_json::to_value(&res)
        .map_err(|e| format!("Falha ao serializar resposta: {}", e))?;
    Ok(val)
}
