# Kubernetes

The repository ships a Helm chart ([`deploy/helm/db-mcp-gateway`](https://github.com/developerz-ai/db-mcp-gateway/tree/main/deploy/helm/db-mcp-gateway)), a minimal kustomize base mirroring it ([`deploy/kustomize/base`](https://github.com/developerz-ai/db-mcp-gateway/tree/main/deploy/kustomize/base)), Prometheus alerts, a Grafana dashboard and a runbook ([`deploy/`](https://github.com/developerz-ai/db-mcp-gateway/tree/main/deploy)). The chart is installed from a checkout; it is not yet published to a chart repository.

**Requires Kubernetes ≥ 1.30**: the pod's `preStop` hook is the native `sleep` action (`PodLifecycleSleepAction`, on by default from 1.30). The image is distroless — there is no shell for an `exec` hook. The chart's `kubeVersion` refuses older clusters.

## Install with Helm

Create the Secrets first; the chart only references them and never takes a secret as a value:

```bash
kubectl create namespace gateway
# STATE_DB_URL, SESSION_SIGNING_KEY (>= 32 bytes, the same on every replica), OIDC_CLIENT_SECRET.
# Use your secret manager (external-secrets, sealed-secrets, Vault) in production;
# --from-file keeps the values out of shell history.
kubectl -n gateway create secret generic db-mcp-gateway \
  --from-file=STATE_DB_URL=./state-db-url \
  --from-file=SESSION_SIGNING_KEY=./signing-key \
  --from-file=OIDC_CLIENT_SECRET=./oidc-client-secret
kubectl -n gateway create secret tls db-mcp-gateway-tls --cert=tls.crt --key=tls.key
kubectl -n gateway create secret generic prod-app-ro --from-file=password=./prod-app-ro-password
```

A values file (`my-values.yaml`):

```yaml
oidc:
  issuer: https://idp.example.com
  clientId: db-mcp-gateway
  redirectUrl: https://db-gateway.example.com/auth/callback
tls:
  secretName: db-mcp-gateway-tls
secretMounts:
  - name: prod-app-ro
    secretName: prod-app-ro
    mountPath: /etc/gateway/secrets/prod-app-ro
config: |
  gateway:
    env: production
  servers:
    - name: prod
      kind: postgres
      host: prod-rw.db.internal
      port: 5432
      tls: verify_full
      databases:
        - name: app
          role: mcp_gateway_prod_app_ro
          password: ${FILE:/etc/gateway/secrets/prod-app-ro/password}
  permissions:
    - group: backend-engineers
      grants:
        - { server: prod, database: "*", action: schema_read }
networkPolicy:
  ingress:
    gatewayFrom:
      - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: ingress-nginx } }
  egress:
    stateDb:
      to: [{ ipBlock: { cidr: 10.20.0.0/24 } }]
      ports: [{ port: 5432, protocol: TCP }]
    targets:
      - to: [{ ipBlock: { cidr: 10.30.0.0/16 } }]
        ports: [{ port: 5432, protocol: TCP }]
```

```bash
helm install gateway ./deploy/helm/db-mcp-gateway -n gateway -f my-values.yaml
```

Validate the config before it reaches the cluster: `db-mcp-gateway --check --no-secrets --config config.yml` ([CLI](cli.md)).

## What the chart sets, and why

| Concern | Chart behaviour |
|---|---|
| Replicas | 2, rolling with `maxUnavailable: 0`; PodDisruptionBudget `minAvailable: 1`. No sticky routing needed: login flows, sessions and audit live in the state DB. Optional CPU HPA (`autoscaling.enabled`) |
| Shutdown | `terminationGracePeriodSeconds: 130` = 10 s `preStop` sleep + the gateway's 120 s worst-case drain after `SIGTERM` (80 s requests, 20 s detached audit writes, 2 × 10 s pool close — [spec 09](../initial-idea/09-deployment.md#shutdown)). The sleep lets endpoints drop the pod before it stops accepting work. The chart fails to render a grace period below `120 + preStopSleepSeconds` |
| Probes | HTTPS (`HTTP` with `tls.enabled: false`) on the gateway port: liveness `/healthz`, readiness `/readyz` (state DB reachable, not shutting down). The kubelet does not verify the certificate |
| Startup | `startupProbe` on `/healthz` with `failureThreshold × periodSeconds` ≥ `STATE_DB_CONNECT_TIMEOUT_SECONDS` (`stateDb.connectTimeoutSeconds`, 60) + `startupMarginSeconds` (60): the listener binds only after boot reaches the state DB and runs migrations |
| Security | Pod and container: `runAsNonRoot` (uid 65532, the image's `nonroot`), `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, capabilities `drop: [ALL]`, seccomp `RuntimeDefault` — the `restricted` Pod Security Standard. No service-account token mounted. A 16 MiB `emptyDir` at `/tmp` |
| Config | `config` → ConfigMap mounted at `/etc/gateway/config/config.yml`. A `checksum/config` annotation rolls the pods on change: Kubernetes sends no `SIGHUP` |
| Secrets | `secrets.existingSecret` → `STATE_DB_URL`, `SESSION_SIGNING_KEY`, `OIDC_CLIENT_SECRET` (optional key) as env vars; `secretMounts` → read-only files for `${FILE:…}` refs (re-read on every pool open, so a rotated password needs only a pool reopen); `extraEnv` for anything else in the [env table](quickstart.md#the-environment-variables-the-gateway-reads) |
| TLS | `tls.secretName` (a `kubernetes.io/tls` Secret) mounted at `/etc/gateway/tls`. `tls.certManager.enabled` adds a cert-manager `Certificate` writing that Secret; it needs `tls.certManager.issuerRef.name` and a non-empty `dnsNames`, or the chart refuses to render. The gateway re-reads the PEMs only on `SIGHUP` or restart: wire a reloader annotation (`podAnnotations`) or restart on renewal — `GatewayTlsCertExpiringSoon` catches a renewal that never reached the pod |
| Metrics | `METRICS_BIND=0.0.0.0:9090` behind its own `<release>-metrics` ClusterIP Service — never route an Ingress to it: its labels name every configured database. `metrics.serviceMonitor.enabled` and `metrics.prometheusRule.enabled` add the prometheus-operator resources |
| NetworkPolicy | On by default. Ingress: the gateway port from `networkPolicy.ingress.gatewayFrom` — a non-empty list of peers (ingress controller, agent namespaces), or `any` to open it to every source; the chart refuses it empty. The metrics port only from `metricsFrom` (default: namespace `monitoring`); an empty `metricsFrom` closes the metrics port rather than opening it. Egress: DNS to kube-dns, then `stateDb`, `idp`, `targets[]`, `extra[]` — each `{ to, ports }`. An empty `to` allows every destination on those ports: narrow each to CIDRs or selectors. Syslog audit sinks and GlitchTip go in `extra`. Target egress must be chosen: scoped `targets[]` (each with a non-empty `to`) or `anyTarget.enabled`; the chart refuses neither, an empty `to`, or `anyTarget` alongside a fenced `stateDb.to` |

Every value is documented in [`values.yaml`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/deploy/helm/db-mcp-gateway/values.yaml). Pin the image by digest with `image.digest`.

## Kustomize

`deploy/kustomize/base` renders the chart's defaults as plain manifests (Deployment, two Services, NetworkPolicy, PodDisruptionBudget, generated ConfigMaps). An overlay sets the image tag, `gateway.env` (the `OIDC_*` variables), `config.yml`, narrows the NetworkPolicy, and creates the `db-mcp-gateway` and `db-mcp-gateway-tls` Secrets. Generated ConfigMap names carry a content hash, so a config change rolls the pods.

```bash
kubectl kustomize deploy/kustomize/base
```

## Alerts, dashboard, runbook

| File | Use |
|---|---|
| [`deploy/prometheus/rules.yaml`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/deploy/prometheus/rules.yaml) | A plain rules file (`rule_files:`); the chart wraps it as a `PrometheusRule`. Audit (unavailable, write latency, fallback failures, abandoned, reaper/pruner staleness, stream and log drops), runtime (reload errors, panics, shedding, TLS expiry, login failures), pool saturation and acquire wait, target unavailability, tool outcome ratios |
| [`deploy/grafana/db-mcp-gateway.json`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/deploy/grafana/db-mcp-gateway.json) | Grafana dashboard over the same series; `datasource`, `job` and `db` variables |
| [`deploy/runbook.md`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/deploy/runbook.md) | One section per alert (each alert's `runbook_url`) and per outcome code |

The gateway's series carry no name prefix (`tool_calls`, `pool_size`, `build_info`). If other jobs in the same Prometheus export a series of the same name, add a `job` matcher to the rules; the dashboard already filters on `$job`. The reaper and pruner staleness alerts are per deployment — `job`, `namespace` and `service` (the label a ServiceMonitor adds) — so with a hand-written scrape config that puts several gateway releases under one job, keep a `service` label (`__meta_kubernetes_service_name`) on their targets. The audit-failure alerts also read `audit_failure_recent`, which the gateway holds at 1 for 15 min (`write`) or 30 min (`fallback`) after a failure, so a refusal before a pod's first scrape still fires when that scrape comes within the hold. `tests/deploy_catalogue.rs` pins every series and label these files name to the metric catalogue (`src/startup/metrics/catalogue.rs`).
