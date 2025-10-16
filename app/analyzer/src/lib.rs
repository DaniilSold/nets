use chrono::{DateTime, Duration, Utc};
use collector::{FlowDirection, FlowEvent};
use normalizer::NormalizedFlow;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

pub mod dsl;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub severity: Severity,
    pub rule_id: String,
    pub summary: String,
    pub flow_refs: Vec<String>,
    pub process_ref: Option<String>,
    pub rationale: String,
    pub suggested_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
}

pub struct Analyzer {
    _baseline_window: Duration,
    history: VecDeque<NormalizedFlow>,
    max_history: usize,
    rules: Vec<dsl::Rule>,
}

impl Analyzer {
    pub fn new(baseline_window: Duration, rules: Vec<dsl::Rule>) -> Self {
        let max_history = (baseline_window.num_minutes().max(1)) as usize * 60;
        Self {
            _baseline_window: baseline_window,
            history: VecDeque::with_capacity(max_history),
            max_history,
            rules,
        }
    }

    pub fn ingest(&mut self, flow: NormalizedFlow) -> Vec<Alert> {
        if self.history.len() >= self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(flow.clone());
        self.evaluate_rules(&flow)
    }

    fn evaluate_rules(&self, flow: &NormalizedFlow) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for rule in &self.rules {
            if rule.matches(flow) {
                alerts.push(Alert {
                    id: format!("alert-{}-{}", rule.id, flow.dst_port),
                    ts: Utc::now(),
                    severity: rule.severity.clone(),
                    rule_id: rule.id.clone(),
                    summary: rule.summary.clone().unwrap_or_else(|| "Rule match".into()),
                    flow_refs: vec![format!(
                        "{}:{}->{}:{}",
                        flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port
                    )],
                    process_ref: flow.process.clone(),
                    rationale: rule
                        .rationale
                        .clone()
                        .unwrap_or_else(|| "Matched DSL condition".into()),
                    suggested_action: rule.suggested_action.clone(),
                });
            }
        }
        alerts
    }
}

pub fn detect_listener(flow: &FlowEvent) -> Option<Alert> {
    if flow.direction == FlowDirection::Inbound && flow.state.as_deref() == Some("LISTEN") {
        Some(Alert {
            id: format!("listener-{}-{}", flow.src_ip, flow.src_port),
            ts: Utc::now(),
            severity: Severity::Medium,
            rule_id: "builtin.listener".into(),
            summary: format!("New listener on {}:{}", flow.src_ip, flow.src_port),
            flow_refs: vec![format!("{}:{}", flow.src_ip, flow.src_port)],
            process_ref: flow.process.as_ref().and_then(|p| p.name.clone()),
            rationale: "Listener state observed from collector".into(),
            suggested_action: Some("Validate service legitimacy or quarantine process".into()),
        })
    } else {
        None
    }
}
