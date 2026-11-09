//! Runs the full Phase 12 benchmark suite over the real stack and
//! prints a markdown table. Numbers are machine-dependent: they
//! measure THIS machine's CBOR codec, SQLite and loopback TCP.

use dtn_bench::codec::bench_codec;
use dtn_bench::contact::{
    bench_duplex_contact, bench_tcp_contact, bench_tcp_contact_latency, bench_tcpclv4_contact,
    Framing,
};
use dtn_bench::report::BenchReport;
use dtn_bench::store::bench_store;

fn main() {
    println!("# DTN-Link benchmark suite (Phase 12)");
    println!();
    println!("All numbers are measured live over the real stack: real CBOR,");
    println!("real SQLite, real in-memory links, real loopback TCP.");
    println!();

    let mut reports: Vec<BenchReport> = Vec::new();

    reports.push(bench_codec(64, 2000));
    reports.push(bench_codec(1024, 2000));
    reports.push(bench_codec(16 * 1024, 500));

    let tmp = std::env::temp_dir();
    match bench_store(&tmp, 500, 256) {
        Ok(r) => reports.push(r),
        Err(e) => eprintln!("store benchmark failed: {e}"),
    }

    reports.push(bench_duplex_contact(Framing::LengthPrefix, 200, 512));
    reports.push(bench_duplex_contact(Framing::Kiss, 200, 512));
    match bench_tcp_contact(200, 512) {
        Ok(r) => reports.push(r),
        Err(e) => eprintln!("tcp benchmark failed: {e}"),
    }
    reports.push(bench_tcpclv4_contact(200, 512));

    println!("| benchmark | ops | ops/s | MiB/s |");
    println!("|---|---|---|---|");
    for r in &reports {
        println!("{}", r.to_markdown_row());
    }

    let lat = bench_tcp_contact_latency(50, 256);
    if !lat.is_empty() {
        println!();
        println!(
            "TCP contact latency ({} samples): median {:?}, p95 {:?}, min {:?}, max {:?}",
            lat.len(),
            lat.median().unwrap(),
            lat.p95().unwrap(),
            lat.min().unwrap(),
            lat.max().unwrap()
        );
    }
}
