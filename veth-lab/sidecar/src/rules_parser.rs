use std::io::BufRead;
use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use edn_rs::Edn;
use tracing::warn;
use veth_filter::{FieldDim, Predicate, RuleAction, RuleSpec};

/// Parse an EDN rules file (one rule per EDN map, can span multiple lines).
/// 
/// Format: EDN maps, possibly spanning multiple lines for readability
/// ```edn
/// {:constraints [(= proto 17) (= src-port 53)] 
///  :actions [(rate-limit 500)] 
///  :priority 190}
/// ```
/// Comments (lines starting with `;`) and blank lines are ignored.
/// The parser accumulates lines until a complete EDN map is found (balanced braces).
pub(crate) fn parse_rules_file(path: &std::path::Path) -> Result<Vec<RuleSpec>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open rules file: {:?}", path))?;
    
    let mut rules = Vec::new();
    let mut skipped = 0;
    let mut accumulator = String::new();
    let mut line_count = 0;
    
    for line in std::io::BufReader::new(file).lines() {
        let line = line?;
        line_count += 1;
        
        let trimmed = line.trim();
        if accumulator.is_empty() && (trimmed.is_empty() || trimmed.starts_with(';')) {
            continue;
        }
        
        accumulator.push_str(&line);
        accumulator.push('\n');
        
        match accumulator.trim().parse::<Edn>() {
            Ok(edn) => {
                match parse_edn_rule(&edn) {
                    Ok(rule) => rules.push(rule),
                    Err(e) => {
                        warn!("Line {}: Failed to parse rule: {}", line_count, e);
                        skipped += 1;
                    }
                }
                accumulator.clear();
            }
            Err(_) => {
                if accumulator.len() > 100_000 {
                    warn!("Line {}: Rule exceeded 100KB, skipping", line_count);
                    accumulator.clear();
                    skipped += 1;
                }
            }
        }
    }
    
    if !accumulator.trim().is_empty() {
        warn!("EOF: Incomplete expression: {}", accumulator.trim());
        skipped += 1;
    }
    
    if skipped > 0 {
        warn!("Skipped {} malformed rules", skipped);
    }
    
    Ok(rules)
}

/// Parse a single EDN rule
fn parse_edn_rule(edn: &Edn) -> Result<RuleSpec> {
    let constraints_edn = edn.get(":constraints")
        .ok_or_else(|| anyhow::anyhow!("Missing :constraints"))?;
    let actions_edn = edn.get(":actions")
        .ok_or_else(|| anyhow::anyhow!("Missing :actions"))?;
    let priority = edn.get(":priority")
        .map(|p| p.to_string().parse::<u8>().unwrap_or(100))
        .unwrap_or(100);
    let comment = edn.get(":comment")
        .map(|c| {
            let mut s = c.to_string();
            s = s.trim_matches('"').to_string();
            if s.len() > 256 {
                s.truncate(256);
            }
            s
        });
    let label = edn.get(":label")
        .and_then(|l| {
            if let Edn::Vector(vec) = l {
                let items = vec.clone().to_vec();
                if items.len() == 2 {
                    let mut ns = items[0].to_string().trim_matches('"').to_string();
                    let mut name = items[1].to_string().trim_matches('"').to_string();
                    if ns.len() > 64 { ns.truncate(64); }
                    if name.len() > 64 { name.truncate(64); }
                    Some((ns, name))
                } else {
                    None
                }
            } else {
                None
            }
        });
    
    let constraints = parse_edn_constraints(constraints_edn)?;
    let actions = parse_edn_actions(actions_edn)?;
    
    if constraints.is_empty() {
        anyhow::bail!("Rule has no constraints");
    }
    
    if actions.is_empty() {
        anyhow::bail!("Rule has no actions");
    }
    
    Ok(RuleSpec {
        constraints,
        actions,
        priority,
        comment,
        label,
    })
}

/// Parse EDN constraints vector: [(= proto 17) (= src-port 53)]
fn parse_edn_constraints(edn: &Edn) -> Result<Vec<Predicate>> {
    if let Edn::Vector(vec) = edn {
        let mut constraints = Vec::new();
        for item in vec.clone().to_vec() {
            if let Some(pred) = parse_edn_predicate(&item)? {
                constraints.push(pred);
            }
        }
        Ok(constraints)
    } else {
        anyhow::bail!("constraints must be a vector")
    }
}

/// Parse a single predicate s-expression: (= proto 17)
fn parse_edn_predicate(edn: &Edn) -> Result<Option<Predicate>> {
    let list = match edn {
        Edn::List(lst) => lst.clone().to_vec(),
        Edn::Vector(vec) => vec.clone().to_vec(),
        _ => anyhow::bail!("Predicate must be a list or vector, got: {:?}", edn),
    };
    
    if list.len() < 2 {
        anyhow::bail!("Predicate must have at least 2 elements");
    }
    
    let op = list[0].to_string();
    
    match op.as_str() {
        "protocol-match" => {
            if list.len() != 3 {
                anyhow::bail!("protocol-match requires exactly 3 elements, got {}", list.len());
            }
            let match_val = parse_field_value(&list[1], FieldDim::Proto)?;
            let mask_val = parse_field_value(&list[2], FieldDim::Proto)?;
            if mask_val == 0xFF {
                return Ok(Some(Predicate::Eq(veth_filter::FieldRef::Dim(FieldDim::Proto), match_val)));
            } else {
                return Ok(Some(Predicate::MaskEq(veth_filter::FieldRef::Dim(FieldDim::Proto), mask_val, match_val)));
            }
        }
        "tcp-flags-match" => {
            if list.len() != 3 {
                anyhow::bail!("tcp-flags-match requires exactly 3 elements, got {}", list.len());
            }
            let match_val = parse_field_value(&list[1], FieldDim::TcpFlags)?;
            let mask_val = parse_field_value(&list[2], FieldDim::TcpFlags)?;
            if mask_val == 0xFF {
                return Ok(Some(Predicate::Eq(veth_filter::FieldRef::Dim(FieldDim::TcpFlags), match_val)));
            } else {
                return Ok(Some(Predicate::MaskEq(veth_filter::FieldRef::Dim(FieldDim::TcpFlags), mask_val, match_val)));
            }
        }
        "l4-match" => {
            if list.len() != 4 {
                anyhow::bail!("l4-match requires exactly 4 elements: (l4-match offset match-hex mask-hex), got {}", list.len());
            }
            let offset: u16 = list[1].to_string().parse()
                .with_context(|| format!("l4-match offset must be a number, got: {}", list[1]))?;
            let match_hex = edn_to_hex_string(&list[2])?;
            let mask_hex = edn_to_hex_string(&list[3])?;
            let match_bytes = hex_decode(&match_hex)
                .with_context(|| format!("l4-match: invalid match hex string: {}", match_hex))?;
            let mask_bytes = hex_decode(&mask_hex)
                .with_context(|| format!("l4-match: invalid mask hex string: {}", mask_hex))?;
            
            if match_bytes.len() != mask_bytes.len() {
                anyhow::bail!("l4-match: match and mask hex strings must be the same length ({} vs {})",
                    match_bytes.len(), mask_bytes.len());
            }
            let length = match_bytes.len();
            if length == 0 || length > veth_filter::MAX_PATTERN_LEN {
                anyhow::bail!("l4-match: pattern length must be 1-{}, got {}", veth_filter::MAX_PATTERN_LEN, length);
            }
            
            if length <= 4 {
                let mut val: u32 = 0;
                let mut mask: u32 = 0;
                for i in 0..length {
                    val = (val << 8) | (match_bytes[i] as u32);
                    mask = (mask << 8) | (mask_bytes[i] as u32);
                }
                val &= mask;
                let all_ff = mask_bytes.iter().all(|&b| b == 0xFF);
                let field_ref = veth_filter::FieldRef::L4Byte { offset, length: length as u8 };
                if all_ff {
                    return Ok(Some(Predicate::Eq(field_ref, val)));
                } else {
                    return Ok(Some(Predicate::MaskEq(field_ref, mask, val)));
                }
            } else {
                let mut pat = veth_filter::BytePattern::default();
                pat.offset = offset;
                pat.length = length as u8;
                for i in 0..length {
                    pat.match_bytes[i] = match_bytes[i] & mask_bytes[i];
                    pat.mask_bytes[i] = mask_bytes[i];
                }
                return Ok(Some(Predicate::RawByteMatch(Box::new(pat))));
            }
        }
        _ => {}
    }
    
    if list.len() < 3 {
        anyhow::bail!("Predicate must have at least 3 elements: (op field value)");
    }
    
    let field = list[1].to_string();
    let dim = parse_field_name(&field)?;
    
    match op.as_str() {
        "=" => {
            if list.len() != 3 {
                anyhow::bail!("= predicate requires exactly 3 elements, got {}", list.len());
            }
            let value = parse_field_value(&list[2], dim)?;
            Ok(Some(Predicate::eq(dim, value)))
        }
        ">" => {
            if list.len() != 3 {
                anyhow::bail!("> predicate requires exactly 3 elements, got {}", list.len());
            }
            let value = parse_field_value(&list[2], dim)?;
            Ok(Some(Predicate::Gt(veth_filter::FieldRef::Dim(dim), value)))
        }
        "<" => {
            if list.len() != 3 {
                anyhow::bail!("< predicate requires exactly 3 elements, got {}", list.len());
            }
            let value = parse_field_value(&list[2], dim)?;
            Ok(Some(Predicate::Lt(veth_filter::FieldRef::Dim(dim), value)))
        }
        ">=" => {
            if list.len() != 3 {
                anyhow::bail!(">= predicate requires exactly 3 elements, got {}", list.len());
            }
            let value = parse_field_value(&list[2], dim)?;
            Ok(Some(Predicate::Gte(veth_filter::FieldRef::Dim(dim), value)))
        }
        "<=" => {
            if list.len() != 3 {
                anyhow::bail!("<= predicate requires exactly 3 elements, got {}", list.len());
            }
            let value = parse_field_value(&list[2], dim)?;
            Ok(Some(Predicate::Lte(veth_filter::FieldRef::Dim(dim), value)))
        }
        "mask" => {
            if list.len() != 3 {
                anyhow::bail!("mask predicate requires exactly 3 elements, got {}", list.len());
            }
            let value = parse_field_value(&list[2], dim)?;
            Ok(Some(Predicate::MaskEq(veth_filter::FieldRef::Dim(dim), value, value)))
        }
        "mask-eq" => {
            if list.len() != 4 {
                anyhow::bail!("mask-eq predicate requires exactly 4 elements, got {}", list.len());
            }
            let mask = parse_field_value(&list[2], dim)?;
            let expected = parse_field_value(&list[3], dim)?;
            Ok(Some(Predicate::MaskEq(veth_filter::FieldRef::Dim(dim), mask, expected)))
        }
        _ => anyhow::bail!("Unsupported predicate operator: {}", op),
    }
}

/// Parse field name from EDN symbol
fn parse_field_name(name: &str) -> Result<FieldDim> {
    match name {
        "proto" => Ok(FieldDim::Proto),
        "src-addr" => Ok(FieldDim::SrcIp),
        "dst-addr" => Ok(FieldDim::DstIp),
        "src-port" => Ok(FieldDim::L4Word0),
        "dst-port" => Ok(FieldDim::L4Word1),
        "tcp-flags" => Ok(FieldDim::TcpFlags),
        "ttl" => Ok(FieldDim::Ttl),
        "df" => Ok(FieldDim::DfBit),
        "tcp-window" => Ok(FieldDim::TcpWindow),
        "ip-id" => Ok(FieldDim::IpId),
        "ip-len" => Ok(FieldDim::IpLen),
        "dscp" => Ok(FieldDim::Dscp),
        "ecn" => Ok(FieldDim::Ecn),
        "mf" => Ok(FieldDim::MfBit),
        "frag-offset" => Ok(FieldDim::FragOffset),
        other => anyhow::bail!("Unknown field: {}", other),
    }
}

/// Extract a hex string from an EDN value (String, Symbol, or keyword).
fn edn_to_hex_string(edn: &Edn) -> Result<String> {
    let s = match edn {
        Edn::Str(s) => s.to_string(),
        Edn::Symbol(s) => s.to_string(),
        _ => edn.to_string(),
    };
    let s = s.trim_matches('"').trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    Ok(s.to_string())
}

/// Decode a hex string into bytes. Each pair of hex chars = one byte.
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("hex string must have even length, got {}", hex.len());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2], 16)
            .with_context(|| format!("invalid hex byte at position {}: '{}'", i, &hex[i..i+2]))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Parse field value from EDN (number or IP string)
fn parse_field_value(edn: &Edn, dim: FieldDim) -> Result<u32> {
    match dim {
        FieldDim::SrcIp | FieldDim::DstIp => {
            let s = match edn {
                Edn::Str(s) => s.to_string(),
                Edn::Symbol(s) => s.to_string(),
                _ => edn.to_string(),
            };
            let s = s.trim_matches('"');
            let ip: Ipv4Addr = s.parse()
                .with_context(|| format!("Invalid IP address: {} (from EDN: {:?})", s, edn))?;
            Ok(u32::from_ne_bytes(ip.octets()))
        }
        _ => {
            let s = edn.to_string();
            s.parse::<u32>()
                .with_context(|| format!("Expected number, got: {}", s))
        }
    }
}

/// Parse EDN actions vector: [(rate-limit 500) (count :name "foo")]
fn parse_edn_actions(edn: &Edn) -> Result<Vec<RuleAction>> {
    if let Edn::Vector(vec) = edn {
        let mut actions = Vec::new();
        for item in vec.clone().to_vec() {
            if let Some(action) = parse_edn_action(&item)? {
                actions.push(action);
            }
        }
        Ok(actions)
    } else {
        anyhow::bail!("actions must be a vector")
    }
}

/// Parse a single action s-expression: (rate-limit 500 :name "foo")
fn parse_edn_action(edn: &Edn) -> Result<Option<RuleAction>> {
    let list = match edn {
        Edn::List(lst) => lst.clone().to_vec(),
        Edn::Vector(vec) => vec.clone().to_vec(),
        _ => anyhow::bail!("Action must be a list or vector, got: {:?}", edn),
    };
    
    if list.is_empty() {
        anyhow::bail!("Action list is empty");
    }
    
    let action_type = list[0].to_string();
    
    match action_type.as_str() {
        "pass" => {
            let name = if list.len() >= 3 && list[1].to_string() == ":name" {
                match &list[2] {
                    Edn::Vector(vec) => {
                        let items = vec.clone().to_vec();
                        if items.len() != 2 {
                            anyhow::bail!(":name must be [namespace, name] with exactly 2 elements");
                        }
                        let ns = items[0].to_string().trim_matches('"').to_string();
                        let n = items[1].to_string().trim_matches('"').to_string();
                        Some((ns, n))
                    }
                    _ => anyhow::bail!(":name must be a vector [namespace, name], got: {:?}", list[2]),
                }
            } else {
                None
            };
            
            Ok(Some(RuleAction::Pass { name }))
        }
        "drop" => {
            let name = if list.len() >= 3 && list[1].to_string() == ":name" {
                match &list[2] {
                    Edn::Vector(vec) => {
                        let items = vec.clone().to_vec();
                        if items.len() != 2 {
                            anyhow::bail!(":name must be [namespace, name] with exactly 2 elements");
                        }
                        let ns = items[0].to_string().trim_matches('"').to_string();
                        let n = items[1].to_string().trim_matches('"').to_string();
                        Some((ns, n))
                    }
                    _ => anyhow::bail!(":name must be a vector [namespace, name], got: {:?}", list[2]),
                }
            } else {
                None
            };
            
            Ok(Some(RuleAction::Drop { name }))
        }
        "rate-limit" => {
            if list.len() < 2 {
                anyhow::bail!("rate-limit requires PPS argument");
            }
            let pps = list[1].to_string().parse::<u32>()
                .with_context(|| "rate-limit PPS must be a number")?;
            
            let name = if list.len() >= 4 && list[2].to_string() == ":name" {
                match &list[3] {
                    Edn::Vector(vec) => {
                        let items = vec.clone().to_vec();
                        if items.len() != 2 {
                            anyhow::bail!(":name must be [namespace, name] with exactly 2 elements");
                        }
                        let ns = items[0].to_string().trim_matches('"').to_string();
                        let n = items[1].to_string().trim_matches('"').to_string();
                        Some((ns, n))
                    }
                    _ => anyhow::bail!(":name must be a vector [namespace, name], got: {:?}", list[3]),
                }
            } else {
                None
            };
            
            Ok(Some(RuleAction::RateLimit { pps, name }))
        }
        "count" => {
            let name = if list.len() >= 3 && list[1].to_string() == ":name" {
                match &list[2] {
                    Edn::Vector(vec) => {
                        let items = vec.clone().to_vec();
                        if items.len() != 2 {
                            anyhow::bail!(":name must be [namespace, name] with exactly 2 elements");
                        }
                        let ns = items[0].to_string().trim_matches('"').to_string();
                        let n = items[1].to_string().trim_matches('"').to_string();
                        Some((ns, n))
                    }
                    _ => anyhow::bail!(":name must be a vector [namespace, name], got: {:?}", list[2]),
                }
            } else {
                None
            };
            
            Ok(Some(RuleAction::Count { name }))
        }
            other => anyhow::bail!("Unknown action type: {}", other),
        }
}
