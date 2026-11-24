//! `GET /admin/v1/permissions/export` + `POST /admin/v1/permissions/diff`
//! (plan 101 O10 e). The export is the whole store, and parallel tests
//! change it between our export and our diff, so diff assertions look only at
//! this test's own subjects.

use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::admin_o10_support::O10;

fn mine<'a>(doc: &'a Value, sub: &str) -> Vec<&'a Value> {
    doc["grants"]
        .as_array()
        .expect("grants")
        .iter()
        .filter(|g| g["subject"]["user"] == sub)
        .collect()
}

/// Entries of a diff `section` about one of `subjects` (`{"user": …}` /
/// `{"group": …}` objects); a `change` entry carries its subject under `key`.
fn ours<'a>(diff: &'a Value, section: &str, subjects: &[Value]) -> Vec<&'a Value> {
    diff[section]
        .as_array()
        .expect("section")
        .iter()
        .filter(|e| {
            let subject = if e["key"].is_object() {
                &e["key"]["subject"]
            } else {
                &e["subject"]
            };
            subjects.contains(subject)
        })
        .collect()
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn export_is_yaml_union_db_and_diffs_clean_against_itself() {
    let mut h = O10::spawn().await;
    let (user_id, sub) = h.user("o10-export", &[]).await;
    let grant = h.wildcard_grant(user_id, json!({ "row_limit": 3 })).await;

    let (status, doc) = h.get("/admin/v1/permissions/export").await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let yaml: Vec<_> = doc["grants"]
        .as_array()
        .expect("grants")
        .iter()
        .filter(|g| g["source"] == "yaml")
        .collect();
    assert_eq!(yaml.len(), 1);
    assert_eq!(yaml[0]["subject"], json!({ "group": "o10-eng" }));
    let db = mine(&doc, &sub);
    assert_eq!(db.len(), 1);
    assert_eq!(db[0]["grant_id"], json!(grant.id));
    assert_eq!(db[0]["database"], "*");
    assert_eq!(db[0]["constraints"]["row_limit"], 3);
    assert_eq!(h.admin_reads("admin.permissions_export").await, 1);

    let subjects = [
        json!({ "user": sub }),
        json!({ "user": "o10-new" }),
        json!({ "group": "o10-eng" }),
    ];
    let (status, diff) = h.post("/admin/v1/permissions/diff", &doc).await;
    assert_eq!(status, StatusCode::OK, "{diff}");
    for section in ["add", "remove", "change"] {
        assert!(
            ours(&diff, section, &subjects).is_empty(),
            "{section}: {diff}"
        );
    }

    // Tighten our grant, drop the YAML one, add a new user grant.
    let mut desired = doc.clone();
    let grants = desired["grants"].as_array_mut().expect("grants");
    grants.retain(|g| g["source"] != "yaml");
    for g in grants.iter_mut().filter(|g| g["subject"]["user"] == sub) {
        g["constraints"]["row_limit"] = json!(1);
    }
    grants.push(json!({ "subject": { "user": "o10-new" }, "server": "prod",
                        "database": "app", "action": "schema_read" }));
    let (_, diff) = h.post("/admin/v1/permissions/diff", &desired).await;
    let add = ours(&diff, "add", &subjects);
    assert_eq!(add.len(), 1, "{diff}");
    assert_eq!(add[0]["subject"]["user"], "o10-new");
    let remove = ours(&diff, "remove", &subjects);
    assert_eq!(remove.len(), 1, "{diff}");
    assert_eq!(remove[0]["subject"]["group"], "o10-eng");
    let change = ours(&diff, "change", &subjects);
    assert_eq!(change.len(), 1, "{diff}");
    assert_eq!(change[0]["desired"][0]["constraints"]["row_limit"], 1);
    assert_eq!(h.admin_reads("admin.permissions_diff").await, 2);

    let (status, err) = h
        .post(
            "/admin/v1/permissions/diff",
            &json!({ "grants": [{ "subject": {}, "server": "prod", "database": "app",
                                  "action": "query_read" }] }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    assert_eq!(
        h.admin_reads("admin.permissions_diff").await,
        2,
        "refused → not read"
    );
    h.cleanup().await;
}
