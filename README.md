# DNS2Tor

**DNS2Tor** is a lightweight, privacy-focused DNS proxy that forwards DNS queries over the Tor network using a SOCKS5 proxy. It listens for UDP-based DNS requests and relays them through anonymized upstream servers, ensuring DNS lookups stay private.

---
<img width="300" height="300" alt="resim" src="https://github.com/user-attachments/assets/1db10cff-46bb-4612-93a1-8984171884e8" />

## Features

* DNS over Tor using SOCKS5
* UDP listener for standard DNS clients
* Configurable rate limiting per IP
* Random selection from multiple upstream DNS servers
* Fully asynchronous (powered by `tokio`)

---

## Installation

### Requirements

* Rust (edition 2021+)
* **Tor must be installed and running locally** (default SOCKS5 port: `127.0.0.1:9050`)

### Build

```bash
cargo build --release
```

### Run

```bash
./target/release/dns2tor \
  --host 127.0.0.1:9053 \
  --tor 127.0.0.1:9050 \
  --upstream 1.1.1.1:53,8.8.8.8:53 \
  --max-req-per-minute 60
```

---

## CLI Options

| Flag                   | Description                                  | Default          |
| ---------------------- | -------------------------------------------- | ---------------- |
| `--host`               | Local UDP address to bind to                 | `127.0.0.1:9053` |
| `--tor`                | SOCKS5 proxy address (Tor)                   | `127.0.0.1:9050` |
| `--upstream`           | Comma-separated list of upstream DNS servers | `1.1.1.1:53`     |
| `--max-req-per-minute` | Max DNS requests allowed per IP per minute   | `60`             |

---

## Example

Point your DNS client (e.g., `dig`, a DNSCrypt stub, or system resolver) to `127.0.0.1:9053`, and all queries will be transparently tunneled through the Tor network.

```bash
dig example.com @127.0.0.1 -p 9053
```

---

## How It Works

DNS2Tor acts as a **local DNS server** that receives DNS queries on your machine (default: `127.0.0.1:9053`) and forwards them to upstream DNS providers (like `1.1.1.1`) **through the Tor network** via a SOCKS5 proxy.

This means:

* When your system or app queries a domain like `example.com`, it sends the request to your local DNS2Tor server.
* DNS2Tor then routes that query to an upstream server (e.g., `1.1.1.1:53`), but **the connection is tunneled through Tor**.
* As a result, **your ISP, network, or any intermediary cannot see the actual destination of your DNS query**, and the upstream server sees it as coming from a Tor exit node.

This setup allows you to use a regular DNS server like `1.1.1.1`, `8.8.8.8`, or any public resolver, but **without exposing your IP or traffic pattern** to them directly.

---

## Why?

Traditional DNS requests are not encrypted and can be monitored or blocked. By tunneling DNS through Tor:

* You hide what domains you're querying.
* You bypass regional censorship.
* You leverage the anonymity benefits of the Tor network.

---

