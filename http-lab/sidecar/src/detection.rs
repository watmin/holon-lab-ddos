//! Detection → RuleSpec compilation.
//!
//! Adapted from veth-lab/sidecar/src/detection.rs for HTTP field dimensions.
//! Takes a list of anomalous fields and compiles them into RuleSpecs.

use serde::{Deserialize, Serialize};

use http_proxy::types::{FieldDim, Predicate, RuleAction, RuleSpec};

/// A single field-level anomaly detection result.
pub struct Detection {
    pub field: String,
    pub value: String,
    /// Rate factor derived from magnitude ratio: lower = more anomalous.
    pub rate_factor: f64,
}

impl Detection {
    /// Convert field/value into a Predicate for the rule tree.
    fn to_predicate(&self) -> Option<Predicate> {
        let dim = match self.field.as_str() {
            "src_ip" => FieldDim::SrcIp,
            "tls_group_hash" => FieldDim::TlsGroupHash,
            "tls_cipher_hash" => FieldDim::TlsCipherHash,
            "tls_ext_order_hash" => FieldDim::TlsExtOrderHash,
            "tls_cipher_set" => FieldDim::TlsCipherSet,
            "tls_ext_set" => FieldDim::TlsExtSet,
            "tls_group_set" => FieldDim::TlsGroupSet,
            "method" => FieldDim::Method,
            "path" => FieldDim::PathPrefix,
            "host" => FieldDim::Host,
            "user_agent" => FieldDim::UserAgent,
            "content_type" => FieldDim::ContentType,
            _ => return None,
        };
        Some(Predicate::eq(dim, &self.value))
    }

    #[allow(dead_code)]
    fn compile_rule_spec(&self, use_rate_limit: bool, estimated_rps: f64) -> Option<RuleSpec> {
        let pred = self.to_predicate()?;
        let allowed_rps = (estimated_rps * self.rate_factor).max(10.0) as u32;
        let action = if use_rate_limit {
            RuleAction::RateLimit { rps: allowed_rps }
        } else {
            RuleAction::block()
        };
        Some(RuleSpec::new(vec![pred], action))
    }
}

/// Compile multiple detections into a compound RuleSpec.
/// For TLS-level detections, use CloseConnection. For request-level, Block/RateLimit.
pub fn compile_compound_rule(
    detections: &[Detection],
    use_rate_limit: bool,
    estimated_rps: f64,
    connection_level: bool,
) -> Option<RuleSpec> {
    if detections.is_empty() { return None; }

    let constraints: Vec<Predicate> = detections.iter()
        .filter_map(|d| d.to_predicate())
        .collect();
    if constraints.is_empty() { return None; }

    let rate_factor = detections[0].rate_factor;
    let allowed_rps = (estimated_rps * rate_factor).max(10.0) as u32;

    let action = if connection_level {
        RuleAction::CloseConnection
    } else if use_rate_limit {
        RuleAction::RateLimit { rps: allowed_rps }
    } else {
        RuleAction::block()
    };

    Some(RuleSpec::new(constraints, action))
}

/// Serializable representation of a rule for engram storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRule {
    pub constraints: Vec<StoredPredicate>,
    pub action: String,
    pub action_rps: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPredicate {
    pub field: String,
    pub op: String,
    pub value: String,
}

impl StoredRule {
    pub fn to_rule_spec(&self) -> Option<RuleSpec> {
        let constraints: Vec<Predicate> = self.constraints.iter()
            .filter_map(|p| {
                    let dim = match p.field.as_str() {
                    "SrcIp" => FieldDim::SrcIp,
                    "Method" => FieldDim::Method,
                    "PathPrefix" => FieldDim::PathPrefix,
                    "Host" => FieldDim::Host,
                    "UserAgent" => FieldDim::UserAgent,
                    "ContentType" => FieldDim::ContentType,
                    "TlsGroupHash" => FieldDim::TlsGroupHash,
                    "TlsCipherHash" => FieldDim::TlsCipherHash,
                    "TlsExtOrderHash" => FieldDim::TlsExtOrderHash,
                    "TlsCipherSet" => FieldDim::TlsCipherSet,
                    "TlsExtSet" => FieldDim::TlsExtSet,
                    "TlsGroupSet" => FieldDim::TlsGroupSet,
                    _ => return None,
                };
                Some(Predicate::eq(dim, &p.value))
            })
            .collect();
        if constraints.is_empty() { return None; }

        let action = match self.action.as_str() {
            "CloseConnection" => RuleAction::CloseConnection,
            "RateLimit" => RuleAction::RateLimit { rps: self.action_rps.unwrap_or(100) },
            _ => RuleAction::block(),
        };

        Some(RuleSpec::new(constraints, action))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(field: &str, value: &str) -> Detection {
        Detection {
            field: field.to_string(),
            value: value.to_string(),
            rate_factor: 0.1,
        }
    }

    #[test]
    fn to_predicate_src_ip() {
        let d = det("src_ip", "10.0.0.1");
        let pred = d.to_predicate().unwrap();
        assert_eq!(pred, Predicate::Eq(FieldDim::SrcIp, "10.0.0.1".to_string()));
    }

    #[test]
    fn to_predicate_method() {
        let d = det("method", "GET");
        let pred = d.to_predicate().unwrap();
        assert_eq!(pred, Predicate::Eq(FieldDim::Method, "GET".to_string()));
    }

    #[test]
    fn to_predicate_tls_group_hash() {
        let d = det("tls_group_hash", "0x001d,0x0017");
        let pred = d.to_predicate().unwrap();
        assert_eq!(pred, Predicate::Eq(FieldDim::TlsGroupHash, "0x001d,0x0017".to_string()));
    }

    #[test]
    fn to_predicate_unknown_field_returns_none() {
        let d = det("unknown_field", "value");
        assert!(d.to_predicate().is_none());
    }

    #[test]
    fn to_predicate_any_string_is_valid() {
        let d = det("src_ip", "not-an-ip");
        let pred = d.to_predicate().unwrap();
        assert_eq!(pred, Predicate::Eq(FieldDim::SrcIp, "not-an-ip".to_string()));
    }

    #[test]
    fn compile_compound_rule_connection_level() {
        let detections = vec![det("src_ip", "10.0.0.1"), det("method", "GET")];
        let rule = compile_compound_rule(&detections, false, 100.0, true).unwrap();
        assert!(matches!(rule.action, RuleAction::CloseConnection));
        assert_eq!(rule.constraints.len(), 2);
    }

    #[test]
    fn compile_compound_rule_rate_limit() {
        let detections = vec![det("src_ip", "10.0.0.1")];
        let rule = compile_compound_rule(&detections, true, 1000.0, false).unwrap();
        assert!(matches!(rule.action, RuleAction::RateLimit { .. }));
    }

    #[test]
    fn compile_compound_rule_block() {
        let detections = vec![det("src_ip", "10.0.0.1")];
        let rule = compile_compound_rule(&detections, false, 1000.0, false).unwrap();
        assert!(matches!(rule.action, RuleAction::Block { status: 403 }));
    }

    #[test]
    fn compile_compound_rule_empty_returns_none() {
        let result = compile_compound_rule(&[], false, 100.0, false);
        assert!(result.is_none());
    }

    #[test]
    fn compile_compound_rule_all_unknown_returns_none() {
        let detections = vec![det("unknown", "val")];
        let result = compile_compound_rule(&detections, false, 100.0, false);
        assert!(result.is_none());
    }

    #[test]
    fn rate_limit_rps_floor() {
        let detections = vec![Detection {
            field: "src_ip".to_string(),
            value: "10.0.0.1".to_string(),
            rate_factor: 0.001, // very low factor
        }];
        let rule = compile_compound_rule(&detections, true, 5.0, false).unwrap();
        if let RuleAction::RateLimit { rps } = rule.action {
            assert!(rps >= 10, "rps should be floored to 10, got {}", rps);
        } else {
            panic!("expected RateLimit");
        }
    }
}
