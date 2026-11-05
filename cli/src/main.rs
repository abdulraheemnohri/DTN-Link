//! dtn-link CLI (Phases 1-5).

use dtn_bpv7::{Bundle, Eid};
use dtn_core::Node;
use dtn_routing::Strategy;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

fn db_path() -> PathBuf {
    let mut p = PathBuf::from(
        std::env::var("DTN_LINK_HOME").unwrap_or_else(|_| ".dtn-link".into()),
    );
    std::fs::create_dir_all(&p).ok();
    p.push("dtn.db");
    p
}

fn strategy_from(s: Option<&str>) -> Strategy {
    match s {
        Some("spray") => Strategy::SprayWait,
        Some("opportunistic") => Strategy::Opportunistic,
        _ => Strategy::Epidemic,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("init") => {
            let node_number: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
            let node = Node::open(node_number, &db_path(), Strategy::Epidemic).expect("failed to init node");
            println!("Initialized node {}", node.eid());
        }
        Some("status") => {
            let node = Node::open(1, &db_path(), Strategy::Epidemic).expect("failed to open node");
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
            let mut node = Node::open(1, &db_path(), Strategy::Epidemic).expect("failed to open node");
            let b = node.send(dest, msg.into_bytes(), lifetime).expect("send failed");
            println!(
                "Sent bundle seq={} -> {} ({} bytes, lifetime {}s)",
                b.primary.creation_ts.1, b.primary.destination, b.encode().len(), lifetime
            );
        }
        Some("receive") => {
            let mut wire = Vec::new();
            std::io::stdin().read_to_end(&mut wire).expect("stdin");
            let mut node = Node::open(1, &db_path(), Strategy::Epidemic).expect("failed to open node");
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
            let node = Node::open(1, &db_path(), Strategy::Epidemic).expect("failed to open node");
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
        Some("forward") => {
            if args.len() < 2 {
                eprintln!("usage: dtn-link forward <dtn://peer> [strategy]");
                std::process::exit(2);
            }
            let peer = Eid::dtn(args[1].trim_start_matches("dtn://"));
            let mut node = Node::open(1, &db_path(), strategy_from(args.get(2).map(String::as_str))).expect("failed to open node");
            for ob in node.select_outbound(&peer).unwrap() {
                println!("{} -> {} [{}]", ob.bundle.primary.source_node,
                    ob.bundle.primary.destination, ob.decision.reason);
            }
        }
        Some("daemon") => {
            let listen = args.iter().position(|a| a == "--listen")
                .and_then(|i| args.get(i + 1)).cloned()
                .unwrap_or_else(|| "0.0.0.0:4556".into());
            let peers: Vec<String> = match args.iter().position(|a| a == "--peers") {
                Some(i) => args.get(i + 1).map(|s| s.split(',').map(String::from).collect()).unwrap_or_default(),
                None => Vec::new(),
            };
            let strategy = args.iter().position(|a| a == "--strategy")
                .and_then(|i| args.get(i + 1)).map(String::as_str);
            let interval: u64 = args.iter().position(|a| a == "--interval")
                .and_then(|i| args.get(i + 1)).and_then(|s| s.parse().ok()).unwrap_or(30);
            let cfg = dtn_daemon::DaemonConfig {
                listen,
                peers,
                strategy: strategy_from(strategy),
                sync_interval: Duration::from_secs(interval),
                db: db_path(),
            };
            dtn_daemon::run(cfg).expect("daemon failed");
        }
        Some("verify") => {
            // usage: dtn-link verify <pubkey-32-byte-hex>   (bundle bytes on stdin)
            let key_hex = match args.get(1) {
                Some(k) => k.clone(),
                None => {
                    eprintln!("usage: dtn-link verify <pubkey-32-byte-hex> < bundle.bin");
                    std::process::exit(2);
                }
            };
            let key_bytes = hex_to_32(&key_hex).unwrap_or_else(|| {
                eprintln!("error: pubkey must be 64 hex characters (32 bytes)");
                std::process::exit(2);
            });
            let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).expect("invalid key");
            let mut wire = Vec::new();
            std::io::stdin().read_to_end(&mut wire).expect("stdin");
            let bundle = Bundle::decode(&wire).unwrap_or_else(|e| {
                eprintln!("invalid bundle: {e}");
                std::process::exit(1);
            });
            match dtn_bpsec::verify_bundle(&bundle, &key) {
                dtn_bpsec::VerifyOutcome::Valid => {
                    println!("VALID — signature verified");
                }
                dtn_bpsec::VerifyOutcome::Invalid => {
                    println!("INVALID — signature does not match (tampered or wrong key)");
                    std::process::exit(1);
                }
                dtn_bpsec::VerifyOutcome::NoIntegrityBlock => {
                    println!("UNSIGNED — bundle carries no integrity block");
                }
                dtn_bpsec::VerifyOutcome::MultipleIntegrityBlocks => {
                    println!("MALFORMED — multiple integrity blocks");
                    std::process::exit(1);
                }
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
        Some("version") => println!("dtn-link 0.3.0 (BPv7, phases 1-5)"),
        _ => {
            eprintln!(
                "dtn-link — decentralized DTN communication (phases 1-5)
usage:
  dtn-link init [node-number]
  dtn-link status
  dtn-link send <dtn://dest> <message> [lifetime-seconds]
  dtn-link receive        (bundle bytes on stdin)
  dtn-link bundles
  dtn-link forward <dtn://peer> [strategy]
  dtn-link daemon --listen 0.0.0.0:4556 [--peers host:port,...] [--strategy epidemic|spray|opportunistic] [--interval 30]
  dtn-link verify <pubkey-hex>   (bundle bytes on stdin)
  dtn-link decode         (bundle bytes on stdin, prints structure)
  dtn-link version"
            );
            std::process::exit(2);
        }
    }
}

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
        let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}
