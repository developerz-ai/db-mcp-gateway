//! #403: the metrics listener outlives `SIGTERM` until the drain is over, so
//! an audit write that fails meanwhile is still scraped.

use std::time::Duration;

use serde_json::json;
use sqlx::PgPool;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep};
use tokio_util::sync::CancellationToken;

use crate::boot_binary::{BinaryGateway, free_port};
use crate::common::audit::latest_audit;
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::{state_db_url, state_pool};
use crate::common::pg_target::config_yaml;

const TOKEN: &str = "dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444448";
const USER_SUB: &str = "service:boot-drain";
/// Inside the 80 s request drain, 20 s detached drain and 2 × 10 s pool close
/// the pod's termination grace is sized for; this call needs a fraction.
const EXIT_WITHIN: Duration = Duration::from_secs(60);
const PATIENCE: Duration = Duration::from_secs(20);

const YAML: &str = "servers:
  - name: target
    kind: postgres
    host: localhost
    port: __TARGET_PORT__
    tls: insecure
    databases:
      - { name: app, role: app, password: app-dev-only }
permissions:
  - group: svc-boot-drain
    grants:
      - { server: target, database: app, action: query_read }
service_accounts:
  - name: boot-drain
    group: svc-boot-drain
    token: dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444448
";

/// Forwards to the state DB while up; down, every connection is closed and
/// new ones are refused.
struct StateDbProxy {
    url: String,
    port: u16,
    upstream: (String, u16),
    down: CancellationToken,
}

impl StateDbProxy {
    async fn start() -> Self {
        let mut url = url::Url::parse(&state_db_url()).expect("state DB url");
        let upstream = (
            url.host_str().expect("host").to_owned(),
            url.port().unwrap_or(5432),
        );
        let port = free_port();
        url.set_host(Some("127.0.0.1")).expect("host");
        url.set_port(Some(port)).expect("port");
        let mut proxy = Self {
            url: url.to_string(),
            port,
            upstream,
            down: CancellationToken::new(),
        };
        proxy.come_up().await;
        proxy
    }

    fn go_down(&self) {
        self.down.cancel();
    }

    async fn come_up(&mut self) {
        let socket = TcpListener::bind(("127.0.0.1", self.port))
            .await
            .expect("bind the proxy port");
        self.down = CancellationToken::new();
        let (down, upstream) = (self.down.clone(), self.upstream.clone());
        tokio::spawn(async move {
            let accept = async {
                while let Ok((client, _)) = socket.accept().await {
                    tokio::spawn(forward(client, upstream.clone(), down.clone()));
                }
            };
            down.run_until_cancelled(accept).await;
        });
    }
}

async fn forward(mut client: TcpStream, upstream: (String, u16), down: CancellationToken) {
    let Ok(mut server) = TcpStream::connect(upstream).await else {
        return;
    };
    let copy = copy_bidirectional(&mut client, &mut server);
    down.run_until_cancelled(copy).await;
}

async fn intents(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_call_intents WHERE user_sub = $1")
        .bind(USER_SUB)
        .fetch_one(pool)
        .await
        .expect("count intents")
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::parallel(world)]
async fn an_audit_failure_during_the_drain_is_scraped() {
    let pool = state_pool().await;
    delete_audit_calls(&pool, USER_SUB).await;
    let mut proxy = StateDbProxy::start().await;
    let metrics_bind = format!("127.0.0.1:{}", free_port());
    let mut gateway = BinaryGateway::spawn(
        &config_yaml(YAML),
        &[
            ("STATE_DB_URL", &proxy.url),
            ("METRICS_BIND", &metrics_bind),
        ],
    );
    gateway.wait_listening().await;
    let metrics_url = format!("http://{metrics_bind}/metrics");

    let sql = json!({ "server": "target", "database": "app", "sql": "SELECT pg_sleep(4)" });
    let call = gateway.call_tool(TOKEN, "run_query", sql, &[]);
    let stop_while_it_runs = async {
        let deadline = Instant::now() + PATIENCE;
        while intents(&pool).await == 0 {
            assert!(Instant::now() < deadline, "{:#?}", gateway.lines());
            sleep(Duration::from_millis(20)).await;
        }
        proxy.go_down();
        gateway.terminate();
    };
    let ((status, body), ()) = tokio::join!(call, stop_while_it_runs);
    assert_eq!(status, 200, "{body}");
    let answer = body["result"]["content"][0]["text"].as_str().expect("text");
    assert!(answer.contains(r#""code":"audit_unavailable""#), "{body}");

    // The completion row failed after SIGTERM; its detached retry, against
    // the same dead state DB, holds the drain open.
    let scrape = reqwest::get(&metrics_url)
        .await
        .expect("metrics are served during the drain")
        .text()
        .await
        .expect("scrape body");
    assert!(
        scrape.contains(r#"audit_failure_recent{kind="write"} 1"#),
        "{scrape}"
    );

    // Back within the retry's acquire window: the row itself is not lost.
    proxy.come_up().await;
    let exit = gateway.wait_exit(EXIT_WITHIN).await;
    assert!(exit.success(), "{exit}: {:#?}", gateway.lines());
    assert!(reqwest::get(&metrics_url).await.is_err());
    let row = latest_audit(&pool, USER_SUB, "run_query", "the drained call").await;
    assert_eq!(row.outcome.as_str(), "audit_unavailable");
    delete_audit_calls(&pool, USER_SUB).await;
}
