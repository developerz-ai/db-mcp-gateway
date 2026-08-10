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
    steal_pct_from_line(line)
}

/// Split from `steal_pct` so the arithmetic is testable without `/proc/stat`.
///
/// The `cpu ` aggregate line is `user nice system idle iowait irq softirq
/// steal [guest guest_nice]`. `guest` is already counted inside `user` and
/// `guest_nice` inside `nice`, so summing every field double-counts guest time
/// and understates the steal fraction — exactly on hosts (KVM) where the
/// `steal > 1.0` warning must fire. Stop at the 8th column.
///
/// Unparsable columns fail the whole computation rather than silently shifting
/// the `steal` index, so a future kernel adding a non-numeric token surfaces
/// as `None` instead of pointing index 7 at the wrong statistic.
fn steal_pct_from_line(line: &str) -> Option<f64> {
    let fields = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(|f| f.parse::<f64>().ok())
        .collect::<Option<Vec<f64>>>()?;
    if fields.len() < 8 {
        return None;
    }
    let steal = fields[7];
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

    #[test]
    fn steal_pct_excludes_guest_from_the_denominator() {
        // user=1000, nice=0, system=100, idle=800, iowait=0, irq=0, softirq=0,
        // steal=100, guest=500, guest_nice=0. Kernel already counts guest inside
        // user, so summing everything would give 2500 and steal/total = 4%.
        // Correct denominator stops at column 8 (2000) — steal is 5%.
        let line = "cpu  1000 0 100 800 0 0 0 100 500 0";
        let pct = steal_pct_from_line(line).expect("well-formed line");
        assert!((pct - 5.0).abs() < 1e-9, "expected 5.0, got {pct}");
    }

    #[test]
    fn steal_pct_rejects_unparsable_columns() {
        // A future kernel inserting a non-numeric token before column 8 would
        // silently make index 7 the wrong statistic; refuse instead.
        let line = "cpu  1000 0 100 800 notanumber 0 0 100";
        assert!(steal_pct_from_line(line).is_none());
    }

    #[test]
    fn steal_pct_is_none_when_the_line_is_short() {
        let line = "cpu  1 2 3 4 5 6 7"; // only 7 fields
        assert!(steal_pct_from_line(line).is_none());
    }
}
