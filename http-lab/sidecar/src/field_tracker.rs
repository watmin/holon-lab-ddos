//! Per-field value tracking with lazy exponential decay.
//!
//! Adapted from veth-lab/sidecar/src/field_tracker.rs for HTTP dimensions.
//! Tracks frequency of each field value (src_ip, method, path, tls_group_hash, etc.)
//! across a sliding window using lazy decay so we don't need to reset per tick.

use std::collections::{HashMap, HashSet};

use crate::detectors::ValueStats;

/// Tracks per-field-value counts with decay across HTTP requests.
pub struct FieldTracker {
    /// field_name → (value_string → stats)
    pub fields: HashMap<String, HashMap<String, ValueStats>>,
    /// Request counter (monotonically increasing)
    pub req_count: u64,
    /// Decay factor per request (e.g. 0.9999 for very slow decay)
    pub alpha: f64,
    /// Max values to track per field before evicting low-count entries
    max_values_per_field: usize,
    /// "field:value" keys that were concentrated during warmup baseline
    baseline_concentrated: HashSet<String>,
}

impl FieldTracker {
    pub fn new(alpha: f64) -> Self {
        Self {
            fields: HashMap::new(),
            req_count: 0,
            alpha,
            max_values_per_field: 10_000,
            baseline_concentrated: HashSet::new(),
        }
    }

    /// Record a set of (field, value) pairs for one HTTP request.
    pub fn observe(&mut self, pairs: &[(&str, String)]) {
        self.observe_with_decay(pairs, self.alpha);
    }

    /// Record a set of (field, value) pairs using a specific decay factor.
    pub fn observe_with_decay(&mut self, pairs: &[(&str, String)], alpha: f64) {
        self.req_count += 1;
        let req = self.req_count;

        for (field, value) in pairs {
            let field_map = self.fields.entry(field.to_string()).or_default();
            field_map.entry(value.clone())
                .or_default()
                .add_one(req, alpha);

            if field_map.len() > self.max_values_per_field {
                let threshold = 0.5;
                field_map.retain(|_, stats| stats.decayed_count(req, alpha) >= threshold);
            }
        }
    }

    /// Get the top N values for a field by decayed count.
    pub fn top_values(&self, field: &str, n: usize) -> Vec<(String, f64)> {
        let req = self.req_count;
        let alpha = self.alpha;
        if let Some(field_map) = self.fields.get(field) {
            let mut entries: Vec<(String, f64)> = field_map.iter()
                .map(|(v, s)| (v.clone(), s.decayed_count(req, alpha)))
                .collect();
            entries.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            entries.truncate(n);
            entries
        } else {
            Vec::new()
        }
    }

    /// Snapshot current concentrated values as the baseline.
    /// Called once at the end of warmup so we don't flag always-dominant values.
    pub fn freeze_baseline(&mut self, threshold: f64) {
        self.baseline_concentrated.clear();
        let req = self.req_count;
        let alpha = self.alpha;

        for (field, field_map) in &self.fields {
            let total: f64 = field_map.values()
                .map(|s| s.decayed_count(req, alpha))
                .sum();
            if total < 1.0 { continue; }

            for (value, stats) in field_map {
                let conc = stats.decayed_count(req, alpha) / total;
                if conc >= threshold {
                    self.baseline_concentrated.insert(format!("{}:{}", field, value));
                }
            }
        }
    }

    /// Find field values whose concentration exceeds `threshold`, excluding
    /// values that were already concentrated during baseline.
    pub fn find_concentrated_values(&self, threshold: f64) -> Vec<(String, String, f64)> {
        let req = self.req_count;
        let alpha = self.alpha;
        let mut results = Vec::new();

        for (field, field_map) in &self.fields {
            let total: f64 = field_map.values()
                .map(|s| s.decayed_count(req, alpha))
                .sum();
            if total < 1.0 { continue; }

            for (value, stats) in field_map {
                let conc = stats.decayed_count(req, alpha) / total;
                if conc >= threshold {
                    let key = format!("{}:{}", field, value);
                    if self.baseline_concentrated.contains(&key) {
                        continue;
                    }
                    results.push((field.clone(), value.clone(), conc));
                }
            }
        }

        results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Total decayed requests across all values for a field.
    pub fn total_for_field(&self, field: &str) -> f64 {
        let req = self.req_count;
        let alpha = self.alpha;
        self.fields.get(field)
            .map(|m| m.values().map(|s| s.decayed_count(req, alpha)).sum())
            .unwrap_or(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_tracks_values() {
        let mut tracker = FieldTracker::new(0.9999);
        tracker.observe(&[("method", "GET".to_string())]);
        tracker.observe(&[("method", "GET".to_string())]);
        tracker.observe(&[("method", "POST".to_string())]);

        let top = tracker.top_values("method", 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "GET");
        assert!(top[0].1 > top[1].1);
    }

    #[test]
    fn top_values_ordering() {
        let mut tracker = FieldTracker::new(1.0); // no decay for simplicity
        for _ in 0..10 {
            tracker.observe(&[("ip", "1.1.1.1".to_string())]);
        }
        for _ in 0..5 {
            tracker.observe(&[("ip", "2.2.2.2".to_string())]);
        }
        tracker.observe(&[("ip", "3.3.3.3".to_string())]);

        let top = tracker.top_values("ip", 3);
        assert_eq!(top[0].0, "1.1.1.1");
        assert_eq!(top[1].0, "2.2.2.2");
        assert_eq!(top[2].0, "3.3.3.3");
    }

    #[test]
    fn total_for_field_sums() {
        let mut tracker = FieldTracker::new(1.0);
        tracker.observe(&[("method", "GET".to_string())]);
        tracker.observe(&[("method", "POST".to_string())]);
        tracker.observe(&[("method", "GET".to_string())]);

        let total = tracker.total_for_field("method");
        assert!((total - 3.0).abs() < 0.01);
    }

    #[test]
    fn total_for_missing_field_is_zero() {
        let tracker = FieldTracker::new(0.9999);
        assert_eq!(tracker.total_for_field("nonexistent"), 0.0);
    }

    #[test]
    fn top_values_empty_field() {
        let tracker = FieldTracker::new(0.9999);
        assert!(tracker.top_values("missing", 5).is_empty());
    }

    #[test]
    fn decay_reduces_old_counts() {
        let mut tracker = FieldTracker::new(0.5); // aggressive decay
        tracker.observe(&[("method", "GET".to_string())]);
        // After many more observations of other values, GET count should decay
        for _ in 0..100 {
            tracker.observe(&[("method", "POST".to_string())]);
        }
        let top = tracker.top_values("method", 2);
        // POST should dominate due to recency + count
        assert_eq!(top[0].0, "POST");
        assert!(top[0].1 > top[1].1);
    }
}
