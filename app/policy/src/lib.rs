use analyzer::{Alert, Severity};
use anyhow::{anyhow, Result};
use collector::FlowEvent;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAction {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub quarantine: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineDecision {
    pub process: Option<String>,
    pub ports: Vec<u16>,
    pub expires_in_seconds: u64,
}

pub trait PolicyBackend {
    fn apply(&self, decision: &QuarantineDecision) -> Result<()>;
    fn rollback(&self, decision: &QuarantineDecision) -> Result<()>;
}

#[derive(Default)]
pub struct NoopBackend;

impl PolicyBackend for NoopBackend {
    fn apply(&self, decision: &QuarantineDecision) -> Result<()> {
        info!(?decision, "noop quarantine apply");
        Ok(())
    }

    fn rollback(&self, decision: &QuarantineDecision) -> Result<()> {
        info!(?decision, "noop quarantine rollback");
        Ok(())
    }
}

pub fn recommend_quarantine(alert: &Alert, flow: &FlowEvent) -> Option<QuarantineDecision> {
    if alert.severity == Severity::High {
        Some(QuarantineDecision {
            process: flow.process.as_ref().and_then(|p| p.name.clone()),
            ports: vec![flow.dst_port],
            expires_in_seconds: 600,
        })
    } else {
        None
    }
}

pub fn validate_decision(decision: &QuarantineDecision) -> Result<()> {
    if decision.ports.is_empty() {
        return Err(anyhow!("quarantine must target at least one port"));
    }
    Ok(())
}
