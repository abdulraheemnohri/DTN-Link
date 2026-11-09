//! SQLite storage throughput through the real node engine: bundle
//! creation (Node::send -> store put) plus full-table query passes.

use crate::codec::deterministic_payload;
use crate::report::BenchReport;
use dtn_bpv7::Eid;
use dtn_core::{Node, Strategy};
use std::io;
use std::path::Path;
use std::time::Instant;

fn io_err(e: dtn_core::NodeError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

/// Puts `count` bundles into a real on-disk SQLite store through
/// Node::send (the node's own sequence counter keeps bundle ids
/// unique), then runs `count` full-table query passes over
/// store.all(). The database file is removed afterwards.
pub fn bench_store(db_dir: &Path, count: u64, payload_size: usize) -> io::Result<BenchReport> {
    let path = db_dir.join(format!(
        "dtn-bench-store-{}-{}.db",
        std::process::id(),
        dtn_storage::now()
    ));
    let mut node = Node::open(9, &path, Strategy::Epidemic).map_err(io_err)?;
    let dest = Eid::dtn("bench-dest");

    let mut total_bytes = 0u64;
    let start = Instant::now();
    for _ in 0..count {
        let bundle = node
            .send(dest.clone(), deterministic_payload(payload_size), 3600)
            .map_err(io_err)?;
        total_bytes += bundle.encode().len() as u64;
    }
    for _ in 0..count {
        let rows = node.store.all().expect("store query");
        assert!(!rows.is_empty(), "stored bundles must be queryable");
    }
    let elapsed = start.elapsed();
    drop(node);
    let _ = std::fs::remove_file(&path);
    Ok(BenchReport::new(
        format!(
            "SQLite store ({} puts + {} query passes, {} B payloads)",
            count, count, payload_size
        ),
        count * 2,
        total_bytes,
        elapsed,
    ))
}
