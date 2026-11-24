//! The few numbers an agent reads first off an `EXPLAIN (FORMAT JSON)`
//! plan, so it need not walk the tree: the root's cost and row estimate,
//! which relations are read by a sequential scan, how many nodes there are.

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize, PartialEq)]
pub(super) struct PlanSummary {
    /// The root node's `Total Cost`, in the planner's units.
    total_cost: f64,
    /// The root node's `Plan Rows`, the planner's row estimate.
    plan_rows: f64,
    /// `Relation Name` of every `Seq Scan` node, first occurrence order,
    /// each once.
    seq_scans: Vec<String>,
    /// Plan nodes, the root and every node under `Plans` (sub-plans and
    /// init-plans included).
    node_count: u64,
}

/// The summary of `plan`, the `[{"Plan": {…}}]` Postgres returns; `None`
/// when it has no such root (the plan itself is still the answer).
pub(super) fn summarize(plan: &Value) -> Option<PlanSummary> {
    let root = plan.get(0)?.get("Plan")?;
    let mut summary = PlanSummary {
        total_cost: root.get("Total Cost")?.as_f64()?,
        plan_rows: root.get("Plan Rows")?.as_f64()?,
        seq_scans: Vec::new(),
        node_count: 0,
    };
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        summary.node_count += 1;
        if node.get("Node Type").and_then(Value::as_str) == Some("Seq Scan")
            && let Some(relation) = node.get("Relation Name").and_then(Value::as_str)
            && !summary.seq_scans.iter().any(|seen| seen == relation)
        {
            summary.seq_scans.push(relation.to_owned());
        }
        if let Some(children) = node.get("Plans").and_then(Value::as_array) {
            // Reversed onto the stack, so nodes are visited in plan order.
            pending.extend(children.iter().rev());
        }
    }
    Some(summary)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_join_tree_is_counted_and_its_seq_scans_named_once() {
        let plan = json!([{"Plan": {
            "Node Type": "Hash Join", "Total Cost": 42.5, "Plan Rows": 10,
            "Plans": [
                {"Node Type": "Seq Scan", "Relation Name": "orders",
                 "Total Cost": 20.0, "Plan Rows": 100},
                {"Node Type": "Hash", "Plans": [
                    {"Node Type": "Seq Scan", "Relation Name": "users"},
                    {"Node Type": "Seq Scan", "Relation Name": "orders"}
                ]}
            ]
        }}]);
        assert_eq!(
            summarize(&plan),
            Some(PlanSummary {
                total_cost: 42.5,
                plan_rows: 10.0,
                seq_scans: vec!["orders".into(), "users".into()],
                node_count: 5,
            })
        );
    }

    #[test]
    fn an_index_scan_is_no_seq_scan() {
        let plan = json!([{"Plan": {
            "Node Type": "Index Scan", "Relation Name": "users",
            "Total Cost": 8.17, "Plan Rows": 1
        }}]);
        let summary = summarize(&plan).expect("summary");
        assert!(summary.seq_scans.is_empty());
        assert_eq!(summary.node_count, 1);
    }

    #[test]
    fn a_plan_without_a_root_has_no_summary() {
        assert_eq!(summarize(&json!([])), None);
        assert_eq!(summarize(&json!({"Plan": {}})), None);
        assert_eq!(summarize(&json!([{"Plan": {"Node Type": "Result"}}])), None);
    }
}
