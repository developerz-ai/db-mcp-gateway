//! The Helm chart and the kustomize base against the gateway's contract:
//! shutdown drain, probes, restricted security context, the crate version,
//! and a default config that parses.

use db_mcp_gateway::config::ConfigFile;
use serde_json::Value;

use crate::{read, yaml};

/// Spec 09 §Shutdown: 80 s request drain + 20 s detached audit + 2 × 10 s pool close.
const SHUTDOWN_DRAIN_SECONDS: u64 = 120;

#[test]
fn chart_and_kustomize_keep_the_shutdown_and_security_contract() {
    let values = yaml("deploy/helm/db-mcp-gateway/values.yaml");
    let pre_stop = values["preStopSleepSeconds"].as_u64().unwrap();
    assert!(
        values["terminationGracePeriodSeconds"].as_u64().unwrap()
            >= SHUTDOWN_DRAIN_SECONDS + pre_stop
    );
    assert_restricted(
        &values["podSecurityContext"],
        &values["securityContext"],
        "values.yaml",
    );

    let deployment = yaml("deploy/kustomize/base/deployment.yaml");
    let pod = &deployment["spec"]["template"]["spec"];
    let container = &pod["containers"][0];
    let pre_stop = container["lifecycle"]["preStop"]["sleep"]["seconds"]
        .as_u64()
        .unwrap();
    assert!(
        pod["terminationGracePeriodSeconds"].as_u64().unwrap() >= SHUTDOWN_DRAIN_SECONDS + pre_stop
    );
    assert_restricted(
        &pod["securityContext"],
        &container["securityContext"],
        "kustomize base",
    );
    for (probe, path) in [
        ("startupProbe", "/healthz"),
        ("livenessProbe", "/healthz"),
        ("readinessProbe", "/readyz"),
    ] {
        assert_eq!(
            container[probe]["httpGet"]["path"], path,
            "kustomize {probe}"
        );
        assert_eq!(
            container[probe]["httpGet"]["scheme"], "HTTPS",
            "kustomize {probe}"
        );
    }
    let startup = &container["startupProbe"];
    let budget =
        startup["periodSeconds"].as_u64().unwrap() * startup["failureThreshold"].as_u64().unwrap();
    assert!(
        budget >= 60,
        "kustomize startupProbe shorter than STATE_DB_CONNECT_TIMEOUT_SECONDS"
    );
}

fn assert_restricted(pod: &Value, container: &Value, at: &str) {
    assert_eq!(pod["runAsNonRoot"], true, "{at}: pod runAsNonRoot");
    assert_eq!(
        pod["seccompProfile"]["type"], "RuntimeDefault",
        "{at}: pod seccomp"
    );
    assert_eq!(
        container["readOnlyRootFilesystem"], true,
        "{at}: readOnlyRootFilesystem"
    );
    assert_eq!(
        container["allowPrivilegeEscalation"], false,
        "{at}: allowPrivilegeEscalation"
    );
    assert_eq!(
        container["capabilities"]["drop"],
        serde_json::json!(["ALL"]),
        "{at}: drop ALL"
    );
}

/// A draining pod is not ready, yet still has audit failures to show: its
/// metrics endpoint stays published, its client port does not.
#[test]
fn only_the_metrics_service_publishes_pods_that_are_not_ready() {
    for path in [
        "deploy/helm/db-mcp-gateway/templates/service.yaml",
        "deploy/kustomize/base/service.yaml",
    ] {
        let text = read(path);
        let (client, metrics) = text.split_once("\n---\n").expect("two Services");
        assert!(client.contains("targetPort: gateway"), "{path}");
        assert!(!client.contains("publishNotReadyAddresses"), "{path}");
        assert!(metrics.contains("targetPort: metrics"), "{path}");
        assert!(
            metrics.contains("\n  publishNotReadyAddresses: true\n"),
            "{path}"
        );
        assert!(!metrics.contains("targetPort: gateway"), "{path}");
        assert_eq!(metrics.matches("targetPort:").count(), 1, "{path}");
    }
}

#[test]
fn deploy_pins_the_crate_version_and_parsing_configs() {
    let version = env!("CARGO_PKG_VERSION");
    let chart = yaml("deploy/helm/db-mcp-gateway/Chart.yaml");
    assert_eq!(chart["appVersion"], version, "Chart.yaml appVersion");
    let kustomization = yaml("deploy/kustomize/base/kustomization.yaml");
    assert_eq!(
        kustomization["images"][0]["newTag"], version,
        "kustomize image tag"
    );

    let values = yaml("deploy/helm/db-mcp-gateway/values.yaml");
    let chart_config = values["config"].as_str().unwrap();
    for (at, raw) in [
        ("chart config", chart_config.to_owned()),
        (
            "kustomize config.yml",
            read("deploy/kustomize/base/config.yml"),
        ),
    ] {
        if let Err(err) = ConfigFile::from_yaml_str(&raw) {
            panic!("{at} does not parse: {err}");
        }
    }
}
