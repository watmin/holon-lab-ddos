//! Detection → RuleSpec compilation.
//!
//! Adapted from veth-lab/sidecar/src/detection.rs for HTTP field dimensions.
//! Takes a list of anomalous fields and compiles them into RuleSpecs.

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
        match self.field.as_str() {
            "src_ip" => self.value.parse::<std::net::IpAddr>().ok()
                .map(|ip| Predicate::eq(FieldDim::SrcIp, ip_to_u32(ip))),

            "tls_group_hash" => self.value.parse::<u32>().ok()
                .map(|v| Predicate::eq(FieldDim::TlsGroupHash, v)),

            "tls_cipher_hash" => self.value.parse::<u32>().ok()
                .map(|v| Predicate::eq(FieldDim::TlsCipherHash, v)),

            "tls_ext_order_hash" => self.value.parse::<u32>().ok()
                .map(|v| Predicate::eq(FieldDim::TlsExtOrderHash, v)),

            "method" => Some(Predicate::eq(FieldDim::Method, fnv1a(&self.value))),
            "path" => Some(Predicate::eq(FieldDim::PathPrefix, fnv1a(&self.value))),
            "host" => Some(Predicate::eq(FieldDim::Host, fnv1a(&self.value))),
            "user_agent" => Some(Predicate::eq(FieldDim::UserAgent, fnv1a(&self.value))),
            "content_type" => Some(Predicate::eq(FieldDim::ContentType, fnv1a(&self.value))),

            _ => None,
        }
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

fn ip_to_u32(ip: std::net::IpAddr) -> u32 {
    match ip {
        std::net::IpAddr::V4(v4) => u32::from_ne_bytes(v4.octets()),
        _ => 0,
    }
}

fn fnv1a(s: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in s.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
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
        let expected_ip = u32::from_ne_bytes([10, 0, 0, 1]);
        assert!(matches!(pred, Predicate::Eq(FieldDim::SrcIp, v) if v == expected_ip));
    }

    #[test]
    fn to_predicate_method() {
        let d = det("method", "GET");
        let pred = d.to_predicate().unwrap();
        assert!(matches!(pred, Predicate::Eq(FieldDim::Method, _)));
    }

    #[test]
    fn to_predicate_tls_group_hash() {
        let d = det("tls_group_hash", "12345");
        let pred = d.to_predicate().unwrap();
        assert!(matches!(pred, Predicate::Eq(FieldDim::TlsGroupHash, 12345)));
    }

    #[test]
    fn to_predicate_unknown_field_returns_none() {
        let d = det("unknown_field", "value");
        assert!(d.to_predicate().is_none());
    }

    #[test]
    fn to_predicate_invalid_ip_returns_none() {
        let d = det("src_ip", "not-an-ip");
        assert!(d.to_predicate().is_none());
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
