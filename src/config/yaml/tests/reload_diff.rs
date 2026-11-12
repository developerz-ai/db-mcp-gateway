//! `changed_databases` (which pools a reload evicts) and `boot_fixed_change`
//! (which reloads are refused whole).

use crate::config::yaml::ConfigFile;

fn config(server_extra: &str, db_extra: &str, password: &str, tail: &str) -> ConfigFile {
    let yaml = format!(
        "servers:\n  - {{ name: s, kind: postgres, host: h{server_extra} }}\n  - name: t\n    kind: postgres\n    host: t\n    databases:\n      - {{ name: d, role: ro, password: \"{password}\"{db_extra} }}\n      - {{ name: e, role: ro, password: \"${{ENV:E}}\" }}\n{tail}"
    );
    ConfigFile::from_yaml_str(&yaml).expect("fixture parses")
}

fn base() -> ConfigFile {
    config("", "", "${ENV:D}", "")
}

fn changed(new: &ConfigFile) -> Vec<(String, String)> {
    base().changed_databases(new)
}

#[test]
fn unchanged_config_evicts_nothing() {
    assert!(changed(&base()).is_empty());
}

#[test]
fn each_connection_setting_evicts_only_its_database() {
    let d = vec![("t".to_string(), "d".to_string())];
    for (label, new) in [
        ("password ref", config("", "", "${ENV:D2}", "")),
        ("role", config("", "", "${ENV:D}", "").tap_role()),
        (
            "pool",
            config("", ", pool: { max_connections: 2 }", "${ENV:D}", ""),
        ),
        (
            "auth_database",
            config("", ", auth_database: admin", "${ENV:D}", ""),
        ),
        ("removed", base().without_d()),
    ] {
        assert_eq!(changed(&new), d, "{label}");
    }
}

#[test]
fn server_settings_evict_every_database_on_it() {
    let yaml = base_yaml().replace("host: t", "host: t2");
    let new = ConfigFile::from_yaml_str(&yaml).expect("parses");
    assert_eq!(changed(&new).len(), 2);
}

#[test]
fn literal_passwords_always_count_as_changed() {
    let literal = config("", "", "hunter2", "");
    assert_eq!(literal.changed_databases(&literal).len(), 1);
}

#[test]
fn admin_and_store_driver_are_boot_fixed() {
    let admin = config(
        "",
        "",
        "${ENV:D}",
        "admin: { enabled: true, group: admins }\n",
    );
    assert_eq!(base().boot_fixed_change(&admin), Some("admin"));
    let regrouped = config(
        "",
        "",
        "${ENV:D}",
        "admin: { enabled: true, group: other }\n",
    );
    assert_eq!(admin.boot_fixed_change(&regrouped), Some("admin"));
    let store = config("", "", "${ENV:D}", "permissions_store: { driver: pg }\n");
    assert_eq!(base().boot_fixed_change(&store), Some("permissions_store"));
    // Disabled admin is the same as absent.
    let off = config("", "", "${ENV:D}", "admin: { enabled: false, group: x }\n");
    assert_eq!(base().boot_fixed_change(&off), None);
}

fn base_yaml() -> String {
    "servers:\n  - { name: s, kind: postgres, host: h }\n  - name: t\n    kind: postgres\n    host: t\n    databases:\n      - { name: d, role: ro, password: \"${ENV:D}\" }\n      - { name: e, role: ro, password: \"${ENV:E}\" }\n".to_string()
}

trait Edit {
    fn tap_role(self) -> Self;
    fn without_d(self) -> Self;
}

impl Edit for ConfigFile {
    fn tap_role(mut self) -> Self {
        self.servers[1].databases[0].role = "ro2".to_string();
        self
    }
    fn without_d(mut self) -> Self {
        self.servers[1].databases.remove(0);
        self
    }
}
