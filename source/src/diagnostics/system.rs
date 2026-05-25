use std::net::SocketAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{BufferingMode, CacheStore, Config, HttpListenerMode};

use super::{DiagnosticReport, DiagnosticSeverity};

pub(super) fn diagnose_system(config: &Config, report: &mut DiagnosticReport) {
  diagnose_fd_limit(config, report);
  diagnose_accept_backlog(config, report);
  diagnose_ephemeral_ports(report);
  diagnose_udp_buffers(config, report);
  diagnose_conntrack(config, report);
  diagnose_cgroup_cpu(config, report);
  #[cfg(target_arch = "x86_64")]
  diagnose_x86_64_v3(report);
  diagnose_low_port_capability(config, report);
  diagnose_write_dirs(config, report);
}

fn diagnose_fd_limit(config: &Config, report: &mut DiagnosticReport) {
  let Some(soft) = current_nofile_soft_limit() else {
    return;
  };
  let desired = config
    .limits
    .max_connections
    .saturating_add(config.runtime.accept.workers)
    .saturating_add(config.quic.socket.workers)
    .saturating_add(128);
  if soft < desired as u64 {
    report.push(
      DiagnosticSeverity::Warning,
      "system.nofile_low",
      "system",
      "RLIMIT_NOFILE",
      format!("open-file soft limit {soft} is below configured connection capacity {desired}"),
      "Raise LimitNOFILE, ulimit -n, or lower limits.max_connections for this deployment.",
    );
  }
}

fn current_nofile_soft_limit() -> Option<u64> {
  let raw = std::fs::read_to_string("/proc/self/limits").ok()?;
  raw.lines().find_map(|line| {
    let fields = line.strip_prefix("Max open files")?.trim();
    let soft = fields.split_whitespace().next()?;
    if soft == "unlimited" {
      Some(u64::MAX)
    } else {
      soft.parse::<u64>().ok()
    }
  })
}

fn diagnose_accept_backlog(config: &Config, report: &mut DiagnosticReport) {
  let Some(somaxconn) = read_u64("/proc/sys/net/core/somaxconn") else {
    return;
  };
  if somaxconn < u64::from(config.runtime.accept.backlog) {
    report.push(
      DiagnosticSeverity::Warning,
      "system.somaxconn_low",
      "system",
      "/proc/sys/net/core/somaxconn",
      format!(
        "somaxconn {somaxconn} is below runtime.accept.backlog {}",
        config.runtime.accept.backlog
      ),
      "Raise net.core.somaxconn or lower runtime.accept.backlog so the kernel honors the configured listen backlog.",
    );
  }
}

fn diagnose_ephemeral_ports(report: &mut DiagnosticReport) {
  let Some(raw) = read_trimmed("/proc/sys/net/ipv4/ip_local_port_range") else {
    return;
  };
  let ports = raw
    .split_whitespace()
    .filter_map(|value| value.parse::<u16>().ok())
    .collect::<Vec<_>>();
  if let [start, end] = ports.as_slice() {
    let count = u32::from(*end).saturating_sub(u32::from(*start)) + 1;
    if count < 16_384 {
      report.push(
        DiagnosticSeverity::Warning,
        "system.ephemeral_port_range_narrow",
        "system",
        "/proc/sys/net/ipv4/ip_local_port_range",
        format!("ephemeral port range {start}-{end} has only {count} ports"),
        "Use a wider ip_local_port_range for high outbound upstream concurrency.",
      );
    }
  }
}

fn diagnose_udp_buffers(config: &Config, report: &mut DiagnosticReport) {
  if !config.listeners.http3 && config.webrtc_turn_listeners.is_empty() {
    return;
  }
  let checks = [
    (
      "/proc/sys/net/core/rmem_max",
      config.quic.socket.receive_buffer_bytes,
      "system.udp_receive_buffer_low",
      "receive",
    ),
    (
      "/proc/sys/net/core/wmem_max",
      config.quic.socket.send_buffer_bytes,
      "system.udp_send_buffer_low",
      "send",
    ),
  ];
  for (path, configured, id, label) in checks {
    let Some(value) = read_u64(path) else {
      continue;
    };
    if configured > 0 && value < configured as u64 {
      report.push(
        DiagnosticSeverity::Warning,
        id,
        "system",
        path,
        format!("UDP {label} buffer max {value} is below configured {configured} bytes"),
        "Raise the kernel UDP buffer limit or lower quic.socket buffer settings.",
      );
    }
  }
}

fn diagnose_conntrack(config: &Config, report: &mut DiagnosticReport) {
  let Some(max) = read_u64("/proc/sys/net/netfilter/nf_conntrack_max") else {
    return;
  };
  let desired = (config.limits.max_connections as u64).saturating_mul(2);
  if max < desired {
    report.push(
      DiagnosticSeverity::Warning,
      "system.conntrack_low",
      "system",
      "/proc/sys/net/netfilter/nf_conntrack_max",
      format!("conntrack table limit {max} is below twice limits.max_connections ({desired})"),
      "Raise nf_conntrack_max when the host uses conntrack/NAT for proxy traffic, or confirm conntrack is not on the data path.",
    );
  }
}

fn diagnose_cgroup_cpu(config: &Config, report: &mut DiagnosticReport) {
  let Some(quota_cpus) = cgroup_v2_cpu_quota() else {
    return;
  };
  let available = config.runtime.worker_resolution.available_parallelism as f64;
  if quota_cpus + 0.25 < available {
    report.push(
      DiagnosticSeverity::Warning,
      "system.cpu_quota_parallelism_mismatch",
      "system",
      "/sys/fs/cgroup/cpu.max",
      format!(
        "cgroup CPU quota is about {quota_cpus:.2} CPUs but available_parallelism resolved to {available:.2}"
      ),
      "Check container CPU quota visibility or set explicit runtime worker counts for this deployment.",
    );
  }
}

fn cgroup_v2_cpu_quota() -> Option<f64> {
  let raw = read_trimmed("/sys/fs/cgroup/cpu.max")?;
  let mut parts = raw.split_whitespace();
  let quota = parts.next()?;
  if quota == "max" {
    return None;
  }
  let quota = quota.parse::<f64>().ok()?;
  let period = parts.next()?.parse::<f64>().ok()?;
  (period > 0.0).then_some(quota / period)
}

#[cfg(target_arch = "x86_64")]
fn diagnose_x86_64_v3(report: &mut DiagnosticReport) {
  let Some(raw) = std::fs::read_to_string("/proc/cpuinfo").ok() else {
    return;
  };
  let Some(flags) = raw.lines().find_map(|line| line.strip_prefix("flags")) else {
    return;
  };
  let missing = [
    "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "lzcnt", "movbe",
  ]
  .into_iter()
  .filter(|flag| !flags.split_whitespace().any(|value| value == *flag))
  .collect::<Vec<_>>();
  if !missing.is_empty() {
    report.push(
      DiagnosticSeverity::Info,
      "system.x86_64_v3_flags_missing",
      "system",
      "/proc/cpuinfo",
      format!("CPU flags are missing x86-64-v3 features: {}", missing.join(", ")),
      "Use a baseline image on this host, or deploy x86-64-v3 optimized builds only on compatible nodes.",
    );
  }
}

fn diagnose_low_port_capability(config: &Config, report: &mut DiagnosticReport) {
  let binds = low_port_binds(config);
  if binds.is_empty() || has_cap_net_bind_service() {
    return;
  }
  report.push(
    DiagnosticSeverity::Warning,
    "system.cap_net_bind_service_missing",
    "system",
    "CAP_NET_BIND_SERVICE",
    format!("low-port listeners are configured without effective CAP_NET_BIND_SERVICE: {}", binds.join(", ")),
    "Grant CAP_NET_BIND_SERVICE, use a socket activator, or bind OxiBelt to high ports behind a load balancer.",
  );
}

fn low_port_binds(config: &Config) -> Vec<String> {
  let mut binds = Vec::new();
  push_low_port(
    &mut binds,
    "listeners.https_bind",
    config.listeners.https_bind,
  );
  if config.listeners.http_mode != HttpListenerMode::Off
    && let Some(bind) = config.listeners.http_bind
  {
    push_low_port(&mut binds, "listeners.http_bind", bind);
  }
  if config.admin.enabled {
    push_low_port(&mut binds, "admin.bind", config.admin.bind);
  }
  if config.metrics.enabled {
    push_low_port(&mut binds, "metrics.bind", config.metrics.bind);
  }
  if config.health.enabled {
    push_low_port(&mut binds, "health.bind", config.health.bind);
  }
  for listener in &config.stream_listeners {
    push_low_port(
      &mut binds,
      &format!("stream_listeners.{}.bind", listener.name),
      listener.bind,
    );
  }
  for listener in &config.webrtc_turn_listeners {
    for (field, bind) in [
      ("bind_udp", listener.bind_udp),
      ("bind_tcp", listener.bind_tcp),
      ("bind_tls", listener.bind_tls),
    ] {
      if let Some(bind) = bind {
        push_low_port(
          &mut binds,
          &format!("webrtc_turn_listeners.{}.{}", listener.name, field),
          bind,
        );
      }
    }
  }
  binds
}

fn push_low_port(binds: &mut Vec<String>, label: &str, bind: SocketAddr) {
  if bind.port() != 0 && bind.port() < 1024 {
    binds.push(format!("{label}={bind}"));
  }
}

fn has_cap_net_bind_service() -> bool {
  let Some(raw) = std::fs::read_to_string("/proc/self/status").ok() else {
    return false;
  };
  let Some(hex) = raw.lines().find_map(|line| line.strip_prefix("CapEff:")) else {
    return false;
  };
  let Ok(bits) = u64::from_str_radix(hex.trim(), 16) else {
    return false;
  };
  bits & (1_u64 << 10) != 0
}

fn diagnose_write_dirs(config: &Config, report: &mut DiagnosticReport) {
  if buffering_requires_temp_dir(config)
    && let Some(path) = &config.proxy.buffering.temp_dir
  {
    check_writable_dir(report, "proxy.buffering.temp_dir", path);
  }
  if config.cache.enabled {
    if config.cache.store == CacheStore::Tmpfs {
      let dir = config
        .cache
        .tmpfs_dir
        .as_deref()
        .unwrap_or_else(|| Path::new("/dev/shm/oxibelt-cache"));
      check_writable_dir(report, "cache.tmpfs_dir", dir);
    }
    if config.cache.store.uses_disk()
      && let Some(dir) = &config.cache.disk_dir
    {
      check_writable_dir(report, "cache.disk_dir", dir);
    }
  }
}

fn buffering_requires_temp_dir(config: &Config) -> bool {
  [
    config.proxy.buffering.request,
    config.proxy.buffering.response,
  ]
  .into_iter()
  .any(|mode| mode == BufferingMode::Spool)
    || config.routes.iter().any(|route| {
      route.buffering.request == Some(BufferingMode::Spool)
        || route.buffering.response == Some(BufferingMode::Spool)
    })
}

fn check_writable_dir(report: &mut DiagnosticReport, target: &str, path: &Path) {
  let nonce = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_nanos())
    .unwrap_or_default();
  let probe = path.join(format!(
    ".oxibelt-doctor-write-test-{}-{nonce}",
    std::process::id()
  ));
  match create_write_probe(&probe) {
    Ok(()) => {
      let _ = std::fs::remove_file(probe);
    }
    Err(error) => report.push(
      DiagnosticSeverity::Error,
      "system.write_dir_unavailable",
      "system",
      target,
      format!("{} is not writable: {error}", path.display()),
      "Mount a writable directory for this path or disable the feature requiring runtime writes.",
    ),
  }
}

fn create_write_probe(path: &Path) -> std::io::Result<()> {
  std::fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(path)
    .and_then(|mut file| std::io::Write::write_all(&mut file, b"ok"))
}

fn read_u64(path: &str) -> Option<u64> {
  read_trimmed(path)?.parse().ok()
}

fn read_trimmed(path: &str) -> Option<String> {
  std::fs::read_to_string(path)
    .ok()
    .map(|value| value.trim().to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[cfg(unix)]
  #[test]
  fn write_probe_does_not_follow_existing_symlink() {
    let nonce = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("system time should be after unix epoch")
      .as_nanos();
    let dir = std::env::temp_dir().join(format!(
      "oxibelt-doctor-symlink-test-{}-{nonce}",
      std::process::id(),
    ));
    std::fs::create_dir_all(&dir).expect("temp dir should be created");
    let victim = dir.join("victim");
    let probe = dir.join("probe");
    std::fs::write(&victim, b"secret").expect("victim should be written");
    std::os::unix::fs::symlink(&victim, &probe).expect("probe symlink should be created");

    assert!(create_write_probe(&probe).is_err());
    assert_eq!(
      std::fs::read(&victim).expect("victim should remain readable"),
      b"secret"
    );

    let _ = std::fs::remove_file(probe);
    let _ = std::fs::remove_file(victim);
    let _ = std::fs::remove_dir(dir);
  }
}
