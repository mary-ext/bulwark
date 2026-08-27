//! Transport idle-footprint and burst-latency probe.
//!
//! Run with `cargo run --release --example transport_footprint -p bulwark`.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bulwark_upstream::{PoolEntry, PoolSettings, UpstreamPool};

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn rss_bytes() -> u64 {
    let Ok(statm) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let resident_pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    resident_pages * 4096
}

fn kib(bytes: u64) -> String {
    format!("{:.0} KiB", bytes as f64 / 1024.0)
}
fn mark(label: &str, prev: &mut u64) {
    let now = rss_bytes();
    let delta = now as i64 - *prev as i64;
    let sign = if delta >= 0 { "+" } else { "-" };
    println!(
        "  RSS {label:<28} {:>10}   (Δ {sign}{})",
        kib(now),
        kib(delta.unsigned_abs())
    );
    *prev = now;
}

fn query(name: &str, rtype: RecordType) -> Message {
    let mut m = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    let fqdn = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    let mut q = Query::query(Name::from_str(&fqdn).unwrap(), rtype);
    q.set_query_class(DNSClass::IN);
    m.queries.push(q);
    m
}

fn answer(query: &Message) -> Message {
    let mut resp = query.clone();
    resp.metadata.message_type = MessageType::Response;
    resp.metadata.recursion_available = true;
    if let Some(q) = query.queries.first() {
        resp.metadata.response_code = ResponseCode::NoError;
        resp.answers.push(Record::from_rdata(
            q.name().clone(),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
    }
    resp
}

async fn respond(bytes: &[u8], delay: Duration) -> Option<Vec<u8>> {
    let query = Message::from_vec(bytes).ok()?;
    let out = answer(&query).to_vec().ok()?;
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    Some(out)
}

async fn mock_udp(delay: Duration) -> String {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let data = buf[..n].to_vec();
            let sock = sock.clone();
            tokio::spawn(async move {
                if let Some(out) = respond(&data, delay).await {
                    let _ = sock.send_to(&out, peer).await;
                }
            });
        }
    });
    format!("udp://{addr}")
}

async fn read_prefixed<R: AsyncReadExt + Unpin>(r: &mut R) -> Option<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await.ok()?;
    let n = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

async fn write_prefixed<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &[u8]) -> std::io::Result<()> {
    let mut framed = Vec::with_capacity(msg.len() + 2);
    framed.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    framed.extend_from_slice(msg);
    w.write_all(&framed).await?;
    w.flush().await
}

async fn mock_tcp(delay: Duration) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            stream.set_nodelay(true).ok();
            tokio::spawn(async move {
                while let Some(msg) = read_prefixed(&mut stream).await {
                    if let Some(out) = respond(&msg, delay).await {
                        if write_prefixed(&mut stream, &out).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
    format!("tcp://{addr}")
}

fn report(label: &str, mut ns: Vec<u64>) {
    if ns.is_empty() {
        println!("  {label:<28} (no samples)");
        return;
    }
    ns.sort_unstable();
    let n = ns.len();
    let pct = |q: f64| ns[(((n as f64) * q) as usize).min(n - 1)];
    println!(
        "  {label:<28} p50={:>7.1}µs  p90={:>7.1}  p99={:>7.1}  max={:>7.1}µs",
        pct(0.50) as f64 / 1000.0,
        pct(0.90) as f64 / 1000.0,
        pct(0.99) as f64 / 1000.0,
        ns[n - 1] as f64 / 1000.0,
    );
}

async fn build_pool(spec: &str) -> Arc<UpstreamPool> {
    Arc::new(
        UpstreamPool::build(
            &[PoolEntry {
                spec: spec.to_string(),
                name: Some("mock".into()),
            }],
            PoolSettings {
                query_timeout: Duration::from_secs(5),
                bootstrap: vec![],
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("build pool for {spec}: {e}")),
    )
}

#[tokio::main]
async fn main() {
    let transport = std::env::var("FOOT_TRANSPORT").unwrap_or_else(|_| "udp".into());
    let burst = env_usize("FOOT_BURST", 50);
    let idle_secs = env_usize("FOOT_IDLE_SECS", 5) as u64;
    let delay = Duration::from_micros(env_usize("FOOT_DELAY_US", 0) as u64);
    if let Err(e) = tikv_jemalloc_ctl::background_thread::write(true) {
        eprintln!("  (could not enable jemalloc background_thread: {e})");
    }

    println!("== transport footprint probe ==");
    println!(
        "  transport={transport}  burst={burst}  idle={idle_secs}s  upstream_delay={delay:?}\n"
    );

    let mut rss = rss_bytes();
    mark("baseline", &mut rss);

    let spec = match transport.as_str() {
        "udp" => mock_udp(delay).await,
        "tcp" => mock_tcp(delay).await,
        other => {
            eprintln!("unknown FOOT_TRANSPORT={other} (use: udp | tcp)");
            return;
        }
    };
    mark("mock upstream up", &mut rss);

    let pool = build_pool(&spec).await;
    mark("pool built (not yet dialed)", &mut rss);
    let t = Instant::now();
    let cold = pool
        .resolve(&query("cold-start.probe.example", RecordType::A))
        .await;
    if cold.is_err() {
        eprintln!(
            "  cold resolve FAILED ({:?}) — are loopback sockets allowed here?",
            cold.err()
        );
        return;
    }
    println!(
        "  cold first-miss latency        {:>7.1}µs  (incl. connection dial)",
        t.elapsed().as_nanos() as f64 / 1000.0
    );
    mark("after first miss (dialed)", &mut rss);
    let idx = Arc::new(AtomicUsize::new(0));
    let lat = Arc::new(parking_lot::Mutex::new(Vec::<u64>::with_capacity(burst)));
    let t0 = Instant::now();
    let mut workers = Vec::new();
    for _ in 0..burst.min(16) {
        let pool = pool.clone();
        let idx = idx.clone();
        let lat = lat.clone();
        workers.push(tokio::spawn(async move {
            loop {
                let i = idx.fetch_add(1, Ordering::Relaxed);
                if i >= burst {
                    break;
                }
                let q = query(
                    &format!("b{i}-{}.burst.probe.example", rand::random::<u32>()),
                    RecordType::A,
                );
                let t = Instant::now();
                if pool.resolve(&q).await.is_ok() {
                    lat.lock().push(t.elapsed().as_nanos() as u64);
                }
            }
        }));
    }
    for w in workers {
        let _ = w.await;
    }
    let burst_elapsed = t0.elapsed();
    let lat = Arc::try_unwrap(lat).unwrap().into_inner();
    println!("  burst of {burst} misses in {:?}", burst_elapsed);
    report("burst per-miss latency", lat);
    mark("after burst", &mut rss);
    println!("\n  idling {idle_secs}s with zero traffic ...");
    tokio::time::sleep(Duration::from_secs(idle_secs)).await;
    mark("after idle (retained)", &mut rss);

    println!(
        "\n  Read the (Δ) on 'after first miss' as the per-upstream cost the\n  \
         persistent {transport} transport allocates on first use, and the\n  \
         'after idle' line as how much of it stays resident at rest. Multiply by\n  \
         your upstream count. For plain UDP that buffer is the dominant term and\n  \
         buys no handshake savings; for TLS/QUIC transports the retained state is\n  \
         larger but does save a handshake on the next burst after idle."
    );
    println!("\n== done ==");
}
