//! `logging.stream` sinks and rejected `logging:` keys.

use crate::config::yaml::{ConfigFile, ConfigFileError};

#[test]
fn absent_logging_block_means_no_stream_sinks() {
    let config = ConfigFile::from_yaml_str("servers: []\n").expect("no logging block parses");
    assert!(config.logging.stream.is_empty());
}

#[test]
fn parses_stdout_stream_sink() {
    let config =
        ConfigFile::from_yaml_str("servers: []\nlogging:\n  stream:\n    - kind: stdout\n")
            .expect("stdout stream sink parses");
    assert_eq!(
        config.logging.stream,
        vec![crate::config::StreamSinkConfig::Stdout]
    );
}

#[test]
fn parses_syslog_stream_sink() {
    let config = ConfigFile::from_yaml_str(
            "servers: []\nlogging:\n  stream:\n    - kind: syslog\n      host: syslog.internal\n      port: 514\n",
        )
        .expect("syslog stream sink parses");
    assert_eq!(
        config.logging.stream,
        vec![crate::config::StreamSinkConfig::Syslog {
            host: "syslog.internal".to_string(),
            port: 514
        }]
    );
}

#[test]
fn rejects_syslog_stream_sink_missing_required_fields() {
    for yaml in [
        "servers: []\nlogging:\n  stream:\n    - kind: syslog\n      port: 514\n",
        "servers: []\nlogging:\n  stream:\n    - kind: syslog\n      host: syslog.internal\n",
    ] {
        ConfigFile::from_yaml_str(yaml)
            .expect_err("syslog sink missing host or port must reject at boot");
    }
}

/// Spec 08 §"Resolution order": validation errors refuse to start. A
/// blank/whitespace-only syslog `host` deserializes cleanly (the type is
/// `String`), then the detached delivery task fails DNS on every audit
/// event and drops silently. Reject at the config boundary instead —
/// same meaning-when-present rule as `admin.group` and `auth_database`.
///
/// Asserts the typed `SyslogSinkBlankHost` variant so callers classify
/// this outcome by variant rather than by substring-matching the message.
#[test]
fn rejects_syslog_stream_sink_with_blank_host() {
    for host in ["\"\"", "\"   \""] {
        let yaml = format!(
            "servers: []\nlogging:\n  stream:\n    - kind: syslog\n      host: {host}\n      port: 514\n"
        );
        let err =
            ConfigFile::from_yaml_str(&yaml).expect_err("blank syslog host must reject at boot");
        match err {
            ConfigFileError::SyslogSinkBlankHost { index } => {
                assert_eq!(index, 0);
            }
            other => panic!("expected SyslogSinkBlankHost, got {other:?}"),
        }
    }
}

/// Port `0` is the wildcard "any port" for socket binds, not a valid
/// destination — a `send_to` targeting it fails at delivery time. Reject
/// at boot so operators see the misconfiguration at startup, not in the
/// error log after requests start flowing.
///
/// Asserts the typed `SyslogSinkZeroPort` variant — same variant-not-text
/// rationale as `rejects_syslog_stream_sink_with_blank_host`.
#[test]
fn rejects_syslog_stream_sink_with_zero_port() {
    let yaml = "servers: []\nlogging:\n  stream:\n    - kind: syslog\n      host: syslog.internal\n      port: 0\n";
    let err = ConfigFile::from_yaml_str(yaml).expect_err("port 0 syslog sink must reject at boot");
    match err {
        ConfigFileError::SyslogSinkZeroPort { index } => {
            assert_eq!(index, 0);
        }
        other => panic!("expected SyslogSinkZeroPort, got {other:?}"),
    }
}

/// Multiple sinks are independent and additive — a common real config
/// (mirror to stdout for local debugging AND ship to the SIEM).
#[test]
fn parses_multiple_stream_sinks() {
    let config = ConfigFile::from_yaml_str(
            "servers: []\nlogging:\n  stream:\n    - kind: stdout\n    - kind: syslog\n      host: syslog.internal\n      port: 514\n",
        )
        .expect("multiple stream sinks parse");
    assert_eq!(config.logging.stream.len(), 2);
}

/// `otlp` is documented as roadmap in spec 07 but not implemented
/// (#218) — the parser must reject it, not silently accept config that
/// does nothing. This is exactly the failure mode #217 fixed in the
/// docs; the config layer must not reopen it.
#[test]
fn rejects_unimplemented_stream_sink_kinds() {
    for kind in ["otlp", "kafka"] {
        let yaml = format!("servers: []\nlogging:\n  stream:\n    - kind: {kind}\n");
        ConfigFile::from_yaml_str(&yaml).expect_err(&format!(
            "`{kind}` stream sink must reject — not implemented"
        ));
    }
}

/// Archive isn't implemented yet either (#218) — an operator who copies
/// spec 07's `archive:` block into their YAML must get a boot error, not
/// a gateway that silently accepts a key it never reads.
#[test]
fn rejects_archive_key_under_logging() {
    let yaml = "servers: []\nlogging:\n  archive:\n    kind: s3\n    bucket: b\n";
    ConfigFile::from_yaml_str(yaml).expect_err("archive: must reject — not implemented");
}
