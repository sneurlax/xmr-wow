/// Adjust recipient amounts by subtracting the estimated fee proportionally.
/// The first recipient absorbs any remainder from integer division.
pub fn adjust_recipients_for_fee(
    recipients: &[(String, u64)],
    estimated_fee: u64,
) -> Vec<(String, u64)> {
    if recipients.is_empty() {
        return vec![];
    }
    let fee_per = estimated_fee / recipients.len() as u64;
    let remainder = estimated_fee % recipients.len() as u64;
    recipients
        .iter()
        .enumerate()
        .map(|(i, (addr, amt))| {
            let deduction = fee_per + if i == 0 { remainder } else { 0 };
            (addr.clone(), amt.saturating_sub(deduction))
        })
        .collect()
}

/// Classify a broadcast error string into (is_double_spend, is_retryable).
pub fn classify_broadcast_error(error: &str) -> (bool, bool) {
    let lower = error.to_lowercase();
    let is_double_spend = lower.contains("double spend")
        || lower.contains("already spent")
        || lower.contains("key image already spent");
    let is_retryable = !is_double_spend
        && (lower.contains("connection")
            || lower.contains("timeout")
            || lower.contains("network")
            || lower.contains("failed to fetch"));
    (is_double_spend, is_retryable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_double_spend() {
        let (ds, retry) = classify_broadcast_error("double spend detected");
        assert!(ds);
        assert!(!retry);
    }

    #[test]
    fn classify_already_spent() {
        let (ds, retry) = classify_broadcast_error("output already spent");
        assert!(ds);
        assert!(!retry);
    }

    #[test]
    fn classify_key_image_already_spent() {
        let (ds, retry) = classify_broadcast_error("key image already spent in pool");
        assert!(ds);
        assert!(!retry);
    }

    #[test]
    fn classify_connection_error() {
        let (ds, retry) = classify_broadcast_error("connection refused");
        assert!(!ds);
        assert!(retry);
    }

    #[test]
    fn classify_timeout_error() {
        let (ds, retry) = classify_broadcast_error("request timeout");
        assert!(!ds);
        assert!(retry);
    }

    #[test]
    fn classify_network_error() {
        let (ds, retry) = classify_broadcast_error("network unreachable");
        assert!(!ds);
        assert!(retry);
    }

    #[test]
    fn classify_failed_to_fetch() {
        let (ds, retry) = classify_broadcast_error("failed to fetch from node");
        assert!(!ds);
        assert!(retry);
    }

    #[test]
    fn classify_unknown_error() {
        let (ds, retry) = classify_broadcast_error("some unknown error");
        assert!(!ds);
        assert!(!retry);
    }

    #[test]
    fn classify_case_insensitive() {
        let (ds, _) = classify_broadcast_error("DOUBLE SPEND");
        assert!(ds);
    }

    #[test]
    fn classify_empty_string() {
        let (ds, retry) = classify_broadcast_error("");
        assert!(!ds);
        assert!(!retry);
    }

    #[test]
    fn adjust_single_recipient() {
        let r = vec![("addr1".to_string(), 1_000_000_000_000u64)];
        let adj = adjust_recipients_for_fee(&r, 50_000_000);
        assert_eq!(adj.len(), 1);
        assert_eq!(adj[0].1, 1_000_000_000_000 - 50_000_000);
    }

    #[test]
    fn adjust_multiple_recipients_even() {
        let r = vec![
            ("a".to_string(), 1_000_000_000_000u64),
            ("b".to_string(), 1_000_000_000_000u64),
        ];
        let adj = adjust_recipients_for_fee(&r, 100_000_000);
        assert_eq!(adj[0].1, 1_000_000_000_000 - 50_000_000);
        assert_eq!(adj[1].1, 1_000_000_000_000 - 50_000_000);
    }

    #[test]
    fn adjust_multiple_recipients_remainder() {
        let r = vec![
            ("a".to_string(), 1_000_000_000_000u64),
            ("b".to_string(), 1_000_000_000_000u64),
            ("c".to_string(), 1_000_000_000_000u64),
        ];
        let adj = adjust_recipients_for_fee(&r, 100_000_000);
        assert_eq!(adj[0].1, 1_000_000_000_000 - 33_333_334);
        assert_eq!(adj[1].1, 1_000_000_000_000 - 33_333_333);
        assert_eq!(adj[2].1, 1_000_000_000_000 - 33_333_333);
        let total_deducted: u64 = r.iter().zip(&adj).map(|((_, orig), (_, adj))| orig - adj).sum();
        assert_eq!(total_deducted, 100_000_000);
    }

    #[test]
    fn adjust_saturating_sub() {
        let r = vec![("a".to_string(), 10u64)];
        let adj = adjust_recipients_for_fee(&r, 1_000_000);
        assert_eq!(adj[0].1, 0);
    }

    #[test]
    fn adjust_empty_recipients() {
        let adj = adjust_recipients_for_fee(&[], 50_000_000);
        assert!(adj.is_empty());
    }

    #[test]
    fn adjust_zero_fee() {
        let r = vec![("a".to_string(), 500u64)];
        let adj = adjust_recipients_for_fee(&r, 0);
        assert_eq!(adj[0].1, 500);
    }

    #[test]
    fn adjust_preserves_addresses() {
        let r = vec![
            ("addr_one".to_string(), 100u64),
            ("addr_two".to_string(), 200u64),
        ];
        let adj = adjust_recipients_for_fee(&r, 10);
        assert_eq!(adj[0].0, "addr_one");
        assert_eq!(adj[1].0, "addr_two");
    }
}
