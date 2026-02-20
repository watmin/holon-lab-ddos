use std::net::Ipv4Addr;

use veth_filter::{FieldDim, Predicate, RuleAction, RuleSpec};

/// Detection result with enhanced metadata
pub(crate) struct Detection {
    pub(crate) field: String,
    pub(crate) value: String,
    /// Rate factor from magnitude ratio (1/magnitude_ratio, capped at 1.0)
    /// Purely vector-derived: if we're seeing 100x traffic, rate_factor = 0.01
    pub(crate) rate_factor: f64,
}

impl Detection {
    /// Convert a detection field/value into a Predicate constraint.
    fn to_constraint(&self) -> Option<Predicate> {
        match self.field.as_str() {
            "src_ip" => self.value.parse::<Ipv4Addr>().ok()
                .map(|ip| Predicate::eq(FieldDim::SrcIp, u32::from_ne_bytes(ip.octets()))),
            "dst_ip" => self.value.parse::<Ipv4Addr>().ok()
                .map(|ip| Predicate::eq(FieldDim::DstIp, u32::from_ne_bytes(ip.octets()))),
            "dst_port" => self.value.parse::<u16>().ok()
                .map(|port| Predicate::eq(FieldDim::L4Word1, port as u32)),
            "src_port" => self.value.parse::<u16>().ok()
                .map(|port| Predicate::eq(FieldDim::L4Word0, port as u32)),
            "protocol" => self.value.parse::<u8>().ok()
                .map(|proto| Predicate::eq(FieldDim::Proto, proto as u32)),
            "tcp_flags" => self.value.parse::<u8>().ok()
                .map(|flags| Predicate::eq(FieldDim::TcpFlags, flags as u32)),
            "ttl" => self.value.parse::<u8>().ok()
                .map(|ttl| Predicate::eq(FieldDim::Ttl, ttl as u32)),
            "df_bit" => self.value.parse::<u8>().ok()
                .map(|df| Predicate::eq(FieldDim::DfBit, df as u32)),
            "tcp_window" => self.value.parse::<u16>().ok()
                .map(|win| Predicate::eq(FieldDim::TcpWindow, win as u32)),
            "ip_id" => self.value.parse::<u16>().ok()
                .map(|id| Predicate::eq(FieldDim::IpId, id as u32)),
            "ip_len" => self.value.parse::<u16>().ok()
                .map(|len| Predicate::eq(FieldDim::IpLen, len as u32)),
            "dscp" => self.value.parse::<u8>().ok()
                .map(|d| Predicate::eq(FieldDim::Dscp, d as u32)),
            "ecn" => self.value.parse::<u8>().ok()
                .map(|e| Predicate::eq(FieldDim::Ecn, e as u32)),
            "mf_bit" => self.value.parse::<u8>().ok()
                .map(|mf| Predicate::eq(FieldDim::MfBit, mf as u32)),
            "frag_offset" => self.value.parse::<u16>().ok()
                .map(|fo| Predicate::eq(FieldDim::FragOffset, fo as u32)),
            _ => None,
        }
    }

    /// Compile a single detection into a RuleSpec
    fn compile_rule_spec(&self, use_rate_limit: bool, estimated_pps: f64) -> Option<RuleSpec> {
        let constraint = self.to_constraint()?;
        let allowed_pps = (estimated_pps * self.rate_factor).max(100.0) as u32;
        
        let action = if use_rate_limit { 
            RuleAction::RateLimit { pps: allowed_pps, name: None }
        } else { 
            RuleAction::Drop { name: None }
        };
        
        Some(RuleSpec { 
            constraints: vec![constraint], 
            actions: vec![action], 
            priority: 100,
            comment: None,
            label: None,
        })
    }
}

/// Compile multiple concentrated detections into a compound RuleSpec.
/// Gathers all constraints and produces a single rule.
pub(crate) fn compile_compound_rule(
    detections: &[Detection],
    use_rate_limit: bool,
    estimated_pps: f64,
) -> Option<RuleSpec> {
    if detections.is_empty() { return None; }
    if detections.len() == 1 {
        return detections[0].compile_rule_spec(use_rate_limit, estimated_pps);
    }

    let constraints: Vec<Predicate> = detections.iter()
        .filter_map(|d| d.to_constraint())
        .collect();
    if constraints.is_empty() { return None; }

    let rate_factor = detections[0].rate_factor;
    let allowed_pps = (estimated_pps * rate_factor).max(100.0) as u32;
    
    let action = if use_rate_limit { 
        RuleAction::RateLimit { pps: allowed_pps, name: None }
    } else { 
        RuleAction::Drop { name: None }
    };

    Some(RuleSpec {
        constraints,
        actions: vec![action],
        priority: 100,
        comment: None,
        label: None,
    })
}

/// Generate a unique key for a rule based on constraints + action type (ignoring action params like rate)
pub(crate) fn rule_identity_key(spec: &RuleSpec) -> String {
    let constraints_part = spec.constraints_to_edn();
    let action_type = spec.actions.first().map(|a| match a {
        RuleAction::Drop { .. } => "drop",
        RuleAction::RateLimit { .. } => "rate-limit",
        RuleAction::Pass { .. } => "pass",
        RuleAction::Count { .. } => "count",
    }).unwrap_or("none");
    
    format!("{}::{}", constraints_part, action_type)
}
