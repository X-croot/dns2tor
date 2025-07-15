use anyhow::Result;
use clap::Parser;
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, time::Instant};
use tokio_socks::tcp::Socks5Stream;
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::record_type::RecordType;
use trust_dns_proto::serialize::binary::BinDecodable;
use chrono::Utc;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rand::seq::SliceRandom;
use rand::thread_rng;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9053")]
    host: String,

    #[arg(long, default_value = "127.0.0.1:9050")]
    tor: String,

    #[arg(long, default_value = "1.1.1.1:53")]
    upstream: String,

    #[arg(long, default_value_t = 60)]
    max_req_per_minute: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let listen_addr: SocketAddr = args.host.parse()?;
    let upstream_addrs: Vec<SocketAddr> = args
    .upstream
    .split(',')
    .map(|s| s.parse())
    .collect::<Result<_, _>>()?;
    let socks5_addr = Arc::new(args.tor.clone());

    println!(
        "\x1b[35m{}\x1b[0m",
        r#"
        ____  _   _ ____ ____ _____ ___  ____
        |  _ \| \ | / ___|___ \_   _/ _ \|  _ \
        | | | |  \| \___ \ __) || || | | | |_) |
        | |_| | |\  |___) / __/ | || |_| |  _ <
        |____/|_| \_|____/_____||_| \___/|_| \_\
        "#
    );

    println!("dns2tor is listening on UDP {}", listen_addr);
    println!("SOCKS5 proxy: {}", socks5_addr);
    println!("Upstream DNS servers: {:?}", upstream_addrs);
    println!("Max requests per IP per minute: {}", args.max_req_per_minute);

    let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
    let rate_limiter = Arc::new(DashMap::<std::net::IpAddr, (usize, Instant)>::new());
    let upstream_addrs = Arc::new(upstream_addrs);
    let buf_size = 512;

    loop {
        let mut buf = vec![0u8; buf_size];
        let (len, src) = socket.recv_from(&mut buf).await?;
        let data = buf[..len].to_vec();

        let rl = rate_limiter.clone();
        let upstreams = upstream_addrs.clone();
        let socks5 = socks5_addr.clone();
        let socket_clone = socket.clone();
        let max_req = args.max_req_per_minute;

        tokio::spawn(async move {
            let src_ip = src.ip();
            let now = Instant::now();
            let mut allowed = false;

            if let Some(mut entry) = rl.get_mut(&src_ip) {
                let (count, last_time) = *entry;
                if now.duration_since(last_time).as_secs() > 60 {
                    entry.value_mut().0 = 1;
                    entry.value_mut().1 = now;
                    allowed = true;
                } else if count < max_req {
                    entry.value_mut().0 += 1;
                    allowed = true;
                }
            } else {
                rl.insert(src_ip, (1, now));
                allowed = true;
            }

            if !allowed {
                println!("Rate limit exceeded: {}", src_ip);
                return;
            }

            let domain = parse_domain_from_query(&data).unwrap_or_else(|| "<parse error>".to_string());

            println!(
                "[{}] DNS query from {} for domain: {}",
                Utc::now().format("%Y-%m-%d %H:%M:%S"),
                     src,
                     domain
            );

            let upstream = {
                let mut rng = thread_rng();
                upstreams.choose(&mut rng).unwrap()
            };

            match forward_dns_over_socks5(&data, upstream, &socks5).await {
                Ok(response) => {
                    let ips = parse_ips_from_response(&response);
                    println!(
                        "[{}] Response to {} for domain: {} => IPs: {:?}",
                        Utc::now().format("%Y-%m-%d %H:%M:%S"),
                             src,
                             domain,
                             ips
                    );

                    if let Err(e) = socket_clone.send_to(&response, &src).await {
                        println!("Failed to send response to {}: {}", src, e);
                    }
                }
                Err(e) => {
                    println!("Failed to forward DNS query for {}: {}", domain, e);
                }
            }
        });
    }
}

fn parse_domain_from_query(data: &[u8]) -> Option<String> {
    if let Ok(msg) = Message::from_vec(data) {
        if let Some(query) = msg.queries().first() {
            return Some(query.name().to_utf8());
        }
    }
    None
}

fn parse_ips_from_response(data: &[u8]) -> Vec<String> {
    let mut ips = Vec::new();
    if let Ok(msg) = Message::from_vec(data) {
        for answer in msg.answers() {
            if answer.record_type() == RecordType::A {
                if let Some(rdata) = answer.data() {
                    if let Some(ip) = rdata.ip_addr() {
                        ips.push(ip.to_string());
                    }
                }
            }
        }
    }
    ips
}


async fn forward_dns_over_socks5(query: &[u8], upstream: &SocketAddr, socks5_addr: &str) -> Result<Vec<u8>> {
    let mut stream = Socks5Stream::connect(socks5_addr, *upstream).await?;
    let len_prefix = (query.len() as u16).to_be_bytes();
    stream.write_all(&len_prefix).await?;
    stream.write_all(query).await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await?;

    Ok(resp_buf)
}
