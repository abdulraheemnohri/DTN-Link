//! dtn-link CLI (Phase 1).

use dtn_bpv7::{Bundle, Eid};
use dtn_core::Node;
use std::io::Read;
use std::path::PathBuf;

fn db_path() -> PathBuf {
    let mut p = PathBuf::from(
        std::env::var("DTN_LINK_HOME").unwrap_or_else(|_| ".dtn-link".into()),
    );
    std::fs::create_dir_all(&p).ok();
    p.push("dtn.db");
    p
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("init") => {
            let node_number: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
            let node = Node::open(node_number, &db_path()).expect("failed to init node");
            println!("Initialized node {}", node.eid());
        }
        Some("status") => {
            let node = Node::open(1, &db_path()).expect("failed to open node");
            println!("Node:       {}", node.eid());
            println!("Bundles:    {}", node.store.count().unwrap_or(0));
            println!("Pending:    {}", node.inbox().map(|v| v.len()).unwrap_or(0));
            println!("BP version: {}", dtn_bpv7::BPV7_VERSION);
        }
        Some("send") => {
            if args.len() < 3 {
                eprintln!("usage: dtn-link send <dtn://dest> <message> [lifetime]");
                std::process::exit(2);
            }
            let dest = Eid::dtn(args[1].trim_start_matches("dtn://"));
            let msg = args[2].clone();
            let lifetime: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3600);
            let mut node = Node::open(1, &db_path()).expect("failed to open node");
            let b = node.send(dest, msg.into_bytes(), lifetime).expect("send failed");
            println!(
                "Sent bundle seq={} -> {} ({} bytes, lifetime {}s)",
                b.primary.creation_ts.1, b.primary.destination, b.encode().len(), lifetime
            );
        }
        Some("receive") => {
            let mut wire = Vec::new();
            std::io::stdin().read_to_end(&mut wire).expect("stdin");
            let mut node = Node::open(1, &db_path()).expect("failed to open node");
            match node.receive(&wire) {
                Ok(Some(b)) => {
                    let text = String::from_utf8_lossy(b.payload().unwrap_or(&[])).to_string();
                    println!("Received from {}: {}", b.primary.source_node, text);
                    node.store.mark_delivered(&b.id()).ok();
                }
                Ok(None) => println!("Bundle ignored (duplicate or expired)"),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("bundles") => {
            let node = Node::open(1, &db_path()).expect("failed to open node");
            for b in node.inbox().unwrap() {
                println!(
                    "{} -> {} seq={} len={}",
                    b.primary.source_node,
                    b.primary.destination,
                    b.primary.creation_ts.1,
                    b.payload().map(<[u8]>::len).unwrap_or(0)
                );
            }
        }
        Some("decode") => {
            let mut wire = Vec::new();
            std::io::stdin().read_to_end(&mut wire).expect("stdin");
            match Bundle::decode(&wire) {
                Ok(b) => println!("{b:#?}"),
                Err(e) => {
                    eprintln!("invalid bundle: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("version") => println!("dtn-link 0.1.0 (BPv7, phase 1)"),
        _ => {
            eprintln!(
                "dtn-link — decentralized DTN communication (phase 1)
usage:
  dtn-link init [node-number]
  dtn-link status
  dtn-link send <dtn://dest> <message> [lifetime-seconds]
  dtn-link receive        (bundle bytes on stdin)
  dtn-link bundles
  dtn-link decode         (bundle bytes on stdin, prints structure)
  dtn-link version"
            );
            std::process::exit(2);
        }
    }
}
