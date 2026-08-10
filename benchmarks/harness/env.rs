//! Machine and build provenance, captured into every result file.
//!
//! A latency number without the machine it came from is not a measurement, it
//! is a rumour. Everything here is read at run time from the host rather than
//! configured, so a published table cannot claim hardware it did not run on.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Environment {
    pub cpu_model: String,
    pub cpu_count: usize,
    pub virtualization: String,
    /// Fraction of all CPU time the hypervisor gave to someone else since
    /// boot. The number that decides whether this box can benchmark at all:
    /// near zero means dedicated-in-practice, percent-scale means the results
    /// describe the neighbours.
    pub cpu_steal_pct_since_boot: Option<f64>,
    pub mem_total_gib: Option<f64>,
    pub kernel: String,
    pub os: String,
    pub rustc: String,
    pub gateway_version: String,
    pub git_commit: String,
    /// True when the working tree had uncommitted changes. A dirty tree means
    /// the commit hash does not identify what actually ran.
    pub git_dirty: bool,
}

impl Environment {
    pub fn capture() -> Self {
        Environment {
            cpu_model: cpu_field("model name").unwrap_or_else(|| "unknown".into()),
            cpu_count: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
            virtualization: run("systemd-detect-virt", &[]).unwrap_or_else(|| "unknown".into()),
            cpu_steal_pct_since_boot: steal_pct(),
            mem_total_gib: mem_total_gib(),
            kernel: run("uname", &["-r"]).unwrap_or_else(|| "unknown".into()),
            os: os_pretty_name().unwrap_or_else(|| "unknown".into()),
            rustc: run("rustc", &["--version"]).unwrap_or_else(|| "unknown".into()),
            gateway_version: env!("CARGO_PKG_VERSION").to_string(),
            git_commit: run("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into()),
            git_dirty: run("git", &["status", "--porcelain"])
                .map(|out| !out.is_empty())
                .unwrap_or(true),
        }
    }
}

/// Percentage of total CPU time in the `steal` column of `/proc/stat`.
fn steal_pct() -> Option<f64> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let fields: Vec<f64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|f| f.parse().ok())
        .collect();
    // user nice system idle iowait irq softirq steal — steal is the 8th.
    let steal = *fields.get(7)?;
    let total: f64 = fields.iter().sum();
    (total > 0.0).then(|| 100.0 * steal / total)
}

fn mem_total_gib() -> Option<f64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024.0 / 1024.0)
}

fn cpu_field(key: &str) -> Option<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    cpuinfo
        .lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split(':').nth(1))
        .map(|v| v.trim().to_string())
}

fn os_pretty_name() -> Option<String> {
    let release = std::fs::read_to_string("/etc/os-release").ok()?;
    release
        .lines()
        .find(|l| l.starts_with("PRETTY_NAME="))
        .and_then(|l| l.split('=').nth(1))
        .map(|v| v.trim_matches('"').to_string())
}

/// Best-effort external command. Every caller has a fallback, because a
/// missing `systemd-detect-virt` should degrade one field rather than fail a
/// benchmark run.
fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_fills_build_provenance_even_if_the_host_is_unusual() {
        let env = Environment::capture();
        assert_eq!(env.gateway_version, env!("CARGO_PKG_VERSION"));
        assert!(env.cpu_count > 0);
    }

    #[test]
    fn steal_is_a_percentage_when_proc_is_readable() {
        if let Some(pct) = steal_pct() {
            assert!((0.0..=100.0).contains(&pct), "steal outside 0..100: {pct}");
        }
    }
}
