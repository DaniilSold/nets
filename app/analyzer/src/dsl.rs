use anyhow::{anyhow, Result};
use normalizer::NormalizedFlow;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub severity: Severity,
    pub summary: Option<String>,
    pub rationale: Option<String>,
    pub suggested_action: Option<String>,
    pub expression: String,
}

impl Rule {
    pub fn matches(&self, flow: &NormalizedFlow) -> bool {
        match evaluate_expression(&self.expression, flow) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(rule = %self.id, %err, "rule evaluation failed");
                false
            }
        }
    }
}

/// Very small interpreter that supports equality and membership tests against flow fields.
pub fn evaluate_expression(expr: &str, flow: &NormalizedFlow) -> Result<bool> {
    let tokens: Vec<&str> = expr.split_whitespace().collect();
    if tokens.len() < 3 {
        return Err(anyhow!("invalid expression"));
    }
    let field = tokens[0];
    let op = tokens[1];
    let value = tokens[2].trim_matches('"');
    match field {
        "proc.name" => {
            let proc_name = flow.process.as_deref().unwrap_or("");
            Ok(apply_operator(proc_name, op, value))
        }
        "dst.port" => Ok(apply_operator(&flow.dst_port.to_string(), op, value)),
        "src.ip" => Ok(apply_operator(&flow.src_ip, op, value)),
        "dst.ip" => Ok(apply_operator(&flow.dst_ip, op, value)),
        other if other.starts_with("regex(") => {
            let re_body = other.trim_start_matches("regex(").trim_end_matches(')');
            let re = Regex::new(re_body)?;
            Ok(re.is_match(&flow.dst_ip) || re.is_match(&flow.src_ip))
        }
        _ => Err(anyhow!("unsupported field: {field}")),
    }
}

fn apply_operator(actual: &str, op: &str, expected: &str) -> bool {
    match op {
        "==" => actual == expected,
        "!=" => actual != expected,
        "in" => expected
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(|s| s.trim())
            .any(|candidate| candidate == actual),
        _ => false,
    }
}

pub fn load_rules_from_str(data: &str) -> Result<Vec<Rule>> {
    let rules: Vec<Rule> = serde_yaml::from_str(data)?;
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};

    #[test]
    fn basic_rule_match() {
        let flow = NormalizedFlow {
            window_start: Utc::now(),
            window_end: Utc::now() + Duration::seconds(60),
            proto: "TCP".into(),
            src_ip: "10.0.0.1".into(),
            src_port: 1234,
            dst_ip: "10.0.0.2".into(),
            dst_port: 445,
            direction: collector::FlowDirection::Lateral,
            bytes: 0,
            packets: 0,
            process: Some("notesync.exe".into()),
        };
        let rule = Rule {
            id: "smb-lateral".into(),
            severity: Severity::High,
            summary: None,
            rationale: None,
            suggested_action: None,
            expression: "dst.port == 445".into(),
        };
        assert!(rule.matches(&flow));
    }
}
