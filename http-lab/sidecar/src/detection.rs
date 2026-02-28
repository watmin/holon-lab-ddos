//! Detection → RuleSpec / RuleExpr compilation.
//!
//! Adapted from veth-lab/sidecar/src/detection.rs for HTTP field dimensions.
//! Takes a list of anomalous fields and compiles them into RuleSpecs (old)
//! or RuleExprs (new expression language).
//!
//! Extended with SurpriseDetection → Expr conversion for VSA-probed fields:
//!   Content → `(= (first (header "name")) "value")`
//!   Shape   → `(= (count (first (header "name"))) length)`
//!   Duplicate → `(= (count (header "name")) count)`

use serde::{Deserialize, Serialize};

use http_proxy::expr::{Dimension, Expr, RuleExpr, SimpleDim, Value};
use http_proxy::types::{FieldDim, Predicate, RuleAction, RuleSpec};
use crate::detectors::{DetectionKind, SurpriseDetection};

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
            RuleAction::RateLimit { rps: allowed_rps, name: None }
        } else {
            RuleAction::block()
        };
        Some(RuleSpec::new(vec![pred], action))
    }

    /// Convert field/value into an Expr for the new expression tree.
    pub fn to_expr(&self) -> Option<Expr> {
        let (dim, value) = match self.field.as_str() {
            "src_ip" => (Dimension::src_ip(), Value::str(&self.value)),
            "method" => (Dimension::method(), Value::str(&self.value)),
            "path" => (Dimension::path(), Value::str(&self.value)),
            "host" => (Dimension::header_first("host"), Value::str(&self.value)),
            "user_agent" => (Dimension::header_first("user-agent"), Value::str(&self.value)),
            "content_type" => (Dimension::header_first("content-type"), Value::str(&self.value)),
            "tls_cipher_set" => (
                Dimension::Simple(SimpleDim::TlsCiphers),
                parse_comma_set(&self.value),
            ),
            "tls_ext_set" => (
                Dimension::Simple(SimpleDim::TlsExtTypes),
                parse_comma_set(&self.value),
            ),
            "tls_group_set" => (
                Dimension::Simple(SimpleDim::TlsGroups),
                parse_comma_set(&self.value),
            ),
            "tls_cipher_hash" => (
                Dimension::Simple(SimpleDim::TlsCiphers),
                parse_comma_set(&self.value),
            ),
            "tls_ext_order_hash" => (
                Dimension::Simple(SimpleDim::TlsExtTypes),
                parse_comma_set(&self.value),
            ),
            "tls_group_hash" => (
                Dimension::Simple(SimpleDim::TlsGroups),
                parse_comma_set(&self.value),
            ),
            _ => return None,
        };
        Some(Expr::eq(dim, value))
    }
}

/// Parse a comma-separated hex string into a Value::Set.
fn parse_comma_set(s: &str) -> Value {
    if s.is_empty() {
        return Value::Set(Default::default());
    }
    Value::set_from_strs(s.split(',').map(|v| v.trim()))
}

/// Convert a SurpriseDetection (from VSA drill-down probing) into an Expr.
///
/// Maps (top_name, kind) → Dimension composition:
///   Content + headers       → `(= (first (header "name")) "value")`
///   Content + path_parts    → `(= (nth path-parts idx) "value")`
///   Content + cookies       → `(= (first (cookie "name")) "value")`
///   Shape + header_shapes   → `(= (count (first (header "name"))) len)`
///   Shape + path_shape      → `(= (count (nth path-parts idx)) len)`
///   Duplicate + headers     → `(= (count (header "name")) count)`
pub fn surprise_to_expr(det: &SurpriseDetection) -> Option<Expr> {
    match det.kind {
        DetectionKind::Content => {
            match det.top_name.as_str() {
                "headers" => {
                    Some(Expr::eq(
                        Dimension::header_first(&det.header_name),
                        Value::str(&det.value),
                    ))
                }
                "path_parts" => {
                    if let Some(idx) = det.header_name.strip_prefix("path[").and_then(|s| s.strip_suffix(']')) {
                        if let Ok(i) = idx.parse::<i32>() {
                            return Some(Expr::eq(
                                Dimension::Nth(Box::new(Dimension::Simple(SimpleDim::PathParts)), i),
                                Value::str(&det.value),
                            ));
                        }
                    }
                    None
                }
                "cookies" => {
                    Some(Expr::eq(
                        Dimension::cookie_first(&det.header_name),
                        Value::str(&det.value),
                    ))
                }
                _ => None,
            }
        }
        DetectionKind::Shape => {
            let len: i64 = det.value.parse().ok()?;
            match det.top_name.as_str() {
                "header_shapes" | "headers" => {
                    Some(Expr::eq(
                        Dimension::Count(Box::new(
                            Dimension::First(Box::new(Dimension::Header(det.header_name.clone())))
                        )),
                        Value::num(len),
                    ))
                }
                "path_shape" | "path_parts" => {
                    if let Some(idx) = det.header_name.strip_prefix("path[").and_then(|s| s.strip_suffix(']')) {
                        if let Ok(i) = idx.parse::<i32>() {
                            return Some(Expr::eq(
                                Dimension::Count(Box::new(
                                    Dimension::Nth(Box::new(Dimension::Simple(SimpleDim::PathParts)), i)
                                )),
                                Value::num(len),
                            ));
                        }
                    }
                    None
                }
                "query_shape" => {
                    None
                }
                _ => None,
            }
        }
        DetectionKind::Duplicate => {
            let count: i64 = det.value.parse().ok()?;
            Some(Expr::eq(
                Dimension::Count(Box::new(Dimension::Header(det.header_name.clone()))),
                Value::num(count),
            ))
        }
    }
}

/// Merge FieldTracker-based detections with surprise-based detections into
/// a single constraint list, deduplicating by header name.
pub fn merge_detections_to_exprs(
    field_detections: &[Detection],
    surprise_detections: &[SurpriseDetection],
) -> Vec<Expr> {
    let mut exprs: Vec<Expr> = Vec::new();
    let mut seen_headers: std::collections::HashSet<String> = std::collections::HashSet::new();

    // FieldTracker detections first (they cover the 12 scalar fields)
    for d in field_detections {
        if let Some(expr) = d.to_expr() {
            let key = match d.field.as_str() {
                "host" => "host".to_string(),
                "user_agent" => "user-agent".to_string(),
                "content_type" => "content-type".to_string(),
                _ => d.field.clone(),
            };
            seen_headers.insert(key);
            exprs.push(expr);
        }
    }

    // Surprise detections (content-before-shape, already sorted)
    for sd in surprise_detections {
        if seen_headers.contains(&sd.header_name) {
            continue;
        }
        if let Some(expr) = surprise_to_expr(sd) {
            seen_headers.insert(sd.header_name.clone());
            exprs.push(expr);
        }
    }

    exprs
}

/// Compile merged detections (field + surprise) into a compound RuleExpr.
pub fn compile_merged_rule_expr(
    field_detections: &[Detection],
    surprise_detections: &[SurpriseDetection],
    use_rate_limit: bool,
    estimated_rps: f64,
    connection_level: bool,
) -> Option<RuleExpr> {
    let constraints = merge_detections_to_exprs(field_detections, surprise_detections);
    if constraints.is_empty() { return None; }

    let rate_factor = field_detections.first()
        .map(|d| d.rate_factor)
        .or_else(|| surprise_detections.first().map(|d| d.rate_factor))
        .unwrap_or(1.0);

    let allowed_rps = (estimated_rps * rate_factor).max(10.0) as u32;

    let action = if connection_level {
        RuleAction::CloseConnection { name: None }
    } else if use_rate_limit {
        RuleAction::RateLimit { rps: allowed_rps, name: None }
    } else {
        RuleAction::block()
    };

    Some(RuleExpr::new(constraints, action))
}

/// Compile multiple detections into a compound RuleExpr (new expression tree).
pub fn compile_compound_rule_expr(
    detections: &[Detection],
    use_rate_limit: bool,
    estimated_rps: f64,
    connection_level: bool,
) -> Option<RuleExpr> {
    if detections.is_empty() { return None; }

    let constraints: Vec<Expr> = detections.iter()
        .filter_map(|d| d.to_expr())
        .collect();
    if constraints.is_empty() { return None; }

    let rate_factor = detections[0].rate_factor;
    let allowed_rps = (estimated_rps * rate_factor).max(10.0) as u32;

    let action = if connection_level {
        RuleAction::CloseConnection { name: None }
    } else if use_rate_limit {
        RuleAction::RateLimit { rps: allowed_rps, name: None }
    } else {
        RuleAction::block()
    };

    Some(RuleExpr::new(constraints, action))
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
        RuleAction::CloseConnection { name: None }
    } else if use_rate_limit {
        RuleAction::RateLimit { rps: allowed_rps, name: None }
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
            "CloseConnection" => RuleAction::CloseConnection { name: None },
            "RateLimit" => RuleAction::RateLimit { rps: self.action_rps.unwrap_or(100), name: None },
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
        assert!(matches!(rule.action, RuleAction::CloseConnection { .. }));
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
        assert!(matches!(rule.action, RuleAction::Block { status: 403, .. }));
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
        if let RuleAction::RateLimit { rps, .. } = rule.action {
            assert!(rps >= 10, "rps should be floored to 10, got {}", rps);
        } else {
            panic!("expected RateLimit");
        }
    }

    // -----------------------------------------------------------------------
    // Expression bridge tests
    // -----------------------------------------------------------------------

    #[test]
    fn to_expr_src_ip() {
        let d = det("src_ip", "10.0.0.1");
        let expr = d.to_expr().unwrap();
        assert_eq!(expr.dim, Dimension::src_ip());
        assert_eq!(expr.value, Value::str("10.0.0.1"));
    }

    #[test]
    fn to_expr_method() {
        let d = det("method", "GET");
        let expr = d.to_expr().unwrap();
        assert_eq!(expr.dim, Dimension::method());
        assert_eq!(expr.value, Value::str("GET"));
    }

    #[test]
    fn to_expr_host_maps_to_header_first() {
        let d = det("host", "example.com");
        let expr = d.to_expr().unwrap();
        assert_eq!(expr.dim, Dimension::header_first("host"));
    }

    #[test]
    fn to_expr_user_agent_maps_to_header_first() {
        let d = det("user_agent", "python-requests/2.31.0");
        let expr = d.to_expr().unwrap();
        assert_eq!(expr.dim, Dimension::header_first("user-agent"));
    }

    #[test]
    fn to_expr_content_type_maps_to_header_first() {
        let d = det("content_type", "application/json");
        let expr = d.to_expr().unwrap();
        assert_eq!(expr.dim, Dimension::header_first("content-type"));
    }

    #[test]
    fn to_expr_tls_cipher_set_produces_set_value() {
        let d = det("tls_cipher_set", "0x1301,0x1302,0x1303");
        let expr = d.to_expr().unwrap();
        assert_eq!(expr.dim, Dimension::Simple(SimpleDim::TlsCiphers));
        if let Value::Set(items) = &expr.value {
            assert_eq!(items.len(), 3);
            assert!(items.contains("0x1301"));
            assert!(items.contains("0x1302"));
            assert!(items.contains("0x1303"));
        } else {
            panic!("expected Set, got {:?}", expr.value);
        }
    }

    #[test]
    fn to_expr_tls_ext_set_produces_set_value() {
        let d = det("tls_ext_set", "0x0000,0x000a");
        let expr = d.to_expr().unwrap();
        assert_eq!(expr.dim, Dimension::Simple(SimpleDim::TlsExtTypes));
    }

    #[test]
    fn to_expr_tls_hash_maps_to_set() {
        let d = det("tls_cipher_hash", "0x1301,0x1302");
        let expr = d.to_expr().unwrap();
        assert_eq!(expr.dim, Dimension::Simple(SimpleDim::TlsCiphers));
        assert!(matches!(expr.value, Value::Set(_)));
    }

    #[test]
    fn to_expr_unknown_returns_none() {
        let d = det("unknown_field", "value");
        assert!(d.to_expr().is_none());
    }

    #[test]
    fn compile_compound_rule_expr_basic() {
        let detections = vec![det("src_ip", "10.0.0.1"), det("method", "GET")];
        let rule = compile_compound_rule_expr(&detections, false, 100.0, true).unwrap();
        assert!(matches!(rule.action, RuleAction::CloseConnection { .. }));
        assert_eq!(rule.constraints.len(), 2);
    }

    #[test]
    fn compile_compound_rule_expr_rate_limit() {
        let detections = vec![det("src_ip", "10.0.0.1")];
        let rule = compile_compound_rule_expr(&detections, true, 1000.0, false).unwrap();
        assert!(matches!(rule.action, RuleAction::RateLimit { .. }));
    }

    #[test]
    fn compile_compound_rule_expr_empty_returns_none() {
        assert!(compile_compound_rule_expr(&[], false, 100.0, false).is_none());
    }

    #[test]
    fn compile_compound_rule_expr_unknown_returns_none() {
        let detections = vec![det("unknown", "val")];
        assert!(compile_compound_rule_expr(&detections, false, 100.0, false).is_none());
    }

    #[test]
    fn compile_compound_rule_expr_mixed_tls_http() {
        let detections = vec![
            det("tls_cipher_set", "0x1301,0x1302"),
            det("method", "POST"),
        ];
        let rule = compile_compound_rule_expr(&detections, true, 100.0, false).unwrap();
        let (has_tls, has_http) = rule.layer_count();
        assert!(has_tls);
        assert!(has_http);
    }

    #[test]
    fn parse_comma_set_basic() {
        let v = parse_comma_set("0x1301,0x1302,0x1303");
        if let Value::Set(items) = v {
            assert_eq!(items.len(), 3);
        } else {
            panic!("expected Set");
        }
    }

    #[test]
    fn parse_comma_set_empty() {
        let v = parse_comma_set("");
        if let Value::Set(items) = v {
            assert!(items.is_empty());
        } else {
            panic!("expected Set");
        }
    }

    // -----------------------------------------------------------------------
    // Surprise detection → Expr tests
    // -----------------------------------------------------------------------

    fn sdet(kind: DetectionKind, header_name: &str, value: &str, top_name: &str) -> SurpriseDetection {
        SurpriseDetection {
            kind,
            header_name: header_name.to_string(),
            value: value.to_string(),
            top_name: top_name.to_string(),
            rate_factor: 0.1,
        }
    }

    #[test]
    fn surprise_content_header() {
        let sd = sdet(DetectionKind::Content, "user-agent", "bot/1.0", "headers");
        let expr = surprise_to_expr(&sd).unwrap();
        assert_eq!(expr.dim, Dimension::header_first("user-agent"));
        assert_eq!(expr.value, Value::str("bot/1.0"));
    }

    #[test]
    fn surprise_shape_header() {
        let sd = sdet(DetectionKind::Shape, "user-agent", "26", "header_shapes");
        let expr = surprise_to_expr(&sd).unwrap();
        assert_eq!(
            expr.dim,
            Dimension::Count(Box::new(Dimension::First(Box::new(Dimension::Header("user-agent".to_string())))))
        );
        assert_eq!(expr.value, Value::num(26));
    }

    #[test]
    fn surprise_duplicate_header() {
        let sd = sdet(DetectionKind::Duplicate, "host", "2", "headers");
        let expr = surprise_to_expr(&sd).unwrap();
        assert_eq!(
            expr.dim,
            Dimension::Count(Box::new(Dimension::Header("host".to_string())))
        );
        assert_eq!(expr.value, Value::num(2));
    }

    #[test]
    fn surprise_content_path_part() {
        let sd = sdet(DetectionKind::Content, "path[1]", "api", "path_parts");
        let expr = surprise_to_expr(&sd).unwrap();
        assert_eq!(
            expr.dim,
            Dimension::Nth(Box::new(Dimension::Simple(SimpleDim::PathParts)), 1)
        );
        assert_eq!(expr.value, Value::str("api"));
    }

    #[test]
    fn surprise_shape_path() {
        let sd = sdet(DetectionKind::Shape, "path[1]", "3", "path_shape");
        let expr = surprise_to_expr(&sd).unwrap();
        assert_eq!(
            expr.dim,
            Dimension::Count(Box::new(
                Dimension::Nth(Box::new(Dimension::Simple(SimpleDim::PathParts)), 1)
            ))
        );
        assert_eq!(expr.value, Value::num(3));
    }

    #[test]
    fn surprise_content_cookie() {
        let sd = sdet(DetectionKind::Content, "session", "exploit", "cookies");
        let expr = surprise_to_expr(&sd).unwrap();
        assert_eq!(expr.dim, Dimension::cookie_first("session"));
        assert_eq!(expr.value, Value::str("exploit"));
    }

    #[test]
    fn surprise_unknown_top_returns_none() {
        let sd = sdet(DetectionKind::Content, "foo", "bar", "unknown_top");
        assert!(surprise_to_expr(&sd).is_none());
    }

    #[test]
    fn merge_deduplicates_by_header_name() {
        let field_dets = vec![det("user_agent", "bot/1.0")];
        let surprise_dets = vec![
            sdet(DetectionKind::Content, "user-agent", "bot/1.0", "headers"),
            sdet(DetectionKind::Content, "accept", "text/html", "headers"),
        ];
        let exprs = merge_detections_to_exprs(&field_dets, &surprise_dets);
        assert_eq!(exprs.len(), 2);
    }

    #[test]
    fn compile_merged_rule_expr_basic() {
        let field_dets = vec![det("method", "POST")];
        let surprise_dets = vec![
            sdet(DetectionKind::Shape, "user-agent", "26", "header_shapes"),
        ];
        let rule = compile_merged_rule_expr(&field_dets, &surprise_dets, true, 100.0, false).unwrap();
        assert_eq!(rule.constraints.len(), 2);
        assert!(matches!(rule.action, RuleAction::RateLimit { .. }));
    }
}
