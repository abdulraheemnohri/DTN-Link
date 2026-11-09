//! Benchmark results and latency percentiles.

use std::fmt;
use std::time::Duration;

/// One completed benchmark: how many operations, how many wire bytes,
/// and how long it took. Derived rates are computed on demand.
#[derive(Debug, Clone)]
pub struct BenchReport {
    pub name: String,
    pub iterations: u64,
    pub total_bytes: u64,
    pub elapsed: Duration,
}

impl BenchReport {
    pub fn new(
        name: impl Into<String>,
        iterations: u64,
        total_bytes: u64,
        elapsed: Duration,
    ) -> Self {
        BenchReport { name: name.into(), iterations, total_bytes, elapsed }
    }

    /// Operations per second over the whole run.
    pub fn ops_per_sec(&self) -> f64 {
        if self.elapsed.as_nanos() == 0 {
            return 0.0;
        }
        self.iterations as f64 / self.elapsed.as_secs_f64()
    }

    /// Wire bytes per second over the whole run.
    pub fn bytes_per_sec(&self) -> f64 {
        if self.elapsed.as_nanos() == 0 {
            return 0.0;
        }
        self.total_bytes as f64 / self.elapsed.as_secs_f64()
    }

    /// Wire MiB per second.
    pub fn mib_per_sec(&self) -> f64 {
        self.bytes_per_sec() / (1024.0 * 1024.0)
    }

    pub fn to_markdown_row(&self) -> String {
        format!(
            "| {} | {} | {:.1} | {:.2} |",
            self.name,
            self.iterations,
            self.ops_per_sec(),
            self.mib_per_sec()
        )
    }
}

impl fmt::Display for BenchReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ops in {:?} ({:.1} ops/s, {:.2} MiB/s)",
            self.name,
            self.iterations,
            self.elapsed,
            self.ops_per_sec(),
            self.mib_per_sec()
        )
    }
}

/// A set of latency samples with exact nearest-rank percentile helpers.
#[derive(Debug, Clone, Default)]
pub struct LatencySamples {
    samples: Vec<Duration>,
}

impl LatencySamples {
    pub fn push(&mut self, d: Duration) {
        self.samples.push(d);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn all(&self) -> &[Duration] {
        &self.samples
    }

    /// Nearest-rank percentile; p must lie in (0, 100].
    pub fn percentile(&self, p: f64) -> Option<Duration> {
        if self.samples.is_empty() || !(0.0..=100.0).contains(&p) {
            return None;
        }
        let mut sorted = self.samples.clone();
        sorted.sort();
        let n = sorted.len();
        let rank = ((p / 100.0) * n as f64).ceil() as usize;
        let idx = rank.clamp(1, n) - 1;
        Some(sorted[idx])
    }

    pub fn median(&self) -> Option<Duration> {
        self.percentile(50.0)
    }

    pub fn p95(&self) -> Option<Duration> {
        self.percentile(95.0)
    }

    pub fn min(&self) -> Option<Duration> {
        self.samples.iter().min().copied()
    }

    pub fn max(&self) -> Option<Duration> {
        self.samples.iter().max().copied()
    }
}
