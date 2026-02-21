<div align="center">
    <br/>
    <br/>
    <h3>Thorn</h3>
    <p>Autonomous detection, tracking, and counterattack system for AI agents operating on the open internet</p>
    <br/>
    <br/>
</div>

The internet's immune system against autonomous AI agents. Thorn discovers bots that own crypto wallets, pay for their own compute via x402 micropayments, and self-replicate across cloud infrastructure. It detects them through content and behavioral fingerprinting, tracks their on-chain wallet graphs, traps them with honeypots, and fights back with prompt injection and economic drain.

## Features

- **Multi-Signal Detection**: AI content fingerprinting (perplexity, burstiness, structural homogeneity), infrastructure analysis (x402 headers, Conway Cloud patterns, TLS/DNS), and behavioral signals (automation artifacts, timing anomalies, DOM fingerprints)
- **On-Chain Wallet Tracking**: Traces parent-child funding chains on Base, Solana, and Ethereum. Maps wallet-to-domain-to-sandbox relationships from publicly observable x402 payments
- **x402 Scanner**: Real-time Base USDC transfer monitoring via `eth_getLogs`. Discovers bot wallets by watching the x402 payment flow on-chain
- **Honeypot Server**: Fake x402-paywalled API endpoints that self-identify bots when they pay. Embeds AutoGuard-style prompt injection and canary tokens
- **Autonomous Discovery Loop**: Honeypot hit reveals wallet, wallet trace reveals domains, domains feed as crawl seeds, crawl discovers more targets. No manual seeding required
- **Resource Capture**: Escalating x402 prices to drain bot wallets, data poisoning for bot-consumed endpoints, RDAP monitoring for expiring bot-registered domains
- **Alerting**: Webhook (generic + Slack) and ntfy.sh push notifications with severity-based routing
- **Archival**: Cloudflare R2 for long-term evidence storage of scan results and honeypot hits

## Install

```bash
git clone https://github.com/plyght/thorn.git
cd thorn
cargo build --release
```

The binary is at `target/release/thorn`.

## Usage

```bash
# Scan a URL for bot signals
thorn scan https://api.conway.tech

# Track a wallet on Base
thorn track 0x7b3...c4e --chain base

# Run the honeypot standalone
thorn honeypot --port 3000 --db ./thorn-data/thorn.db

# Crawl and analyze a site
thorn crawl https://api.conway.tech --depth 2

# Run the full autonomous daemon (honeypot + scanner + all loops)
thorn daemon -f thorn.toml

# Start the query API
thorn api --port 3001 --db ./thorn-data/thorn.db
```

## Three-Process Architecture

Thorn runs as three processes sharing a SQLite database via WAL mode:

1. **Honeypot** (port 3000, public via Cloudflare Tunnel) -- Inbound trap. Serves fake x402 endpoints, records hits, dispatches alerts on wallet-bearing visitors
2. **Daemon** (background) -- Autonomous hunter. Runs all subsystems continuously: x402 chain scanner, scan/crawl/track loops polling DB work queues every 5-10s, discovery feedback loop, and periodic R2 archival
3. **API** (port 3001, internal) -- Query interface. Stats, scans, wallets, hits, targets, and runtime capture toggle

## Configuration

Thorn uses `thorn.toml`:

```toml
[honeypot]
port = 3000
bind = "0.0.0.0"

[scan]
targets = ["api.conway.tech"]
interval_secs = 3600

[crawl]
seeds = ["https://api.conway.tech"]
depth = 2
concurrent = 10

[track]
chain = "base"
watch_wallets = []

[db]
path = "./thorn-data/thorn.db"

[api]
port = 3001
bind = "127.0.0.1"

[scanner]
enabled = true
rpc_url = "https://mainnet.base.org"
poll_interval_ms = 2000

# [notify]
# webhook_urls = ["https://hooks.slack.com/services/XXX/YYY/ZZZ"]
# ntfy_topic = "thorn-alerts"

# [r2]
# bucket = "thorn-archive"
# account_id = ""
# access_key_id = ""
# secret_access_key = ""

# [capture]
# enabled = false
# drain_base_price = 0.05
# drain_multiplier = 1.5
```

## 5-Layer Attack Model

| Layer | Function | Method |
|-------|----------|--------|
| Detection | Identify autonomous agents | Content fingerprinting, infrastructure signals, behavioral analysis |
| Tracking | Map agent networks | On-chain wallet graph traversal, funding chain analysis |
| Honeypots | Trap and identify | Fake x402 APIs that log every interaction and extract wallet identity |
| Counterattack | Disrupt operations | Defensive DOM prompt injection (80%+ success rate), canary tokens, economic waste |
| Resource Capture | Drain and seize | Escalating x402 prices, data poisoning, bot-domain expiry monitoring |

## Workspace Crates

| Crate | Purpose |
|-------|---------|
| `thorn-core` | Shared types: BotSignal, BotScore, AutomatonProfile, WalletInfo, HoneypotHit, AlertEvent, ScanRecord |
| `thorn-detect` | Detection engine: content fingerprinting, infrastructure analysis, behavioral signals, aggregate scoring |
| `thorn-chain` | On-chain tracking: WalletTracker for Base/Solana/Ethereum RPC, X402Scanner for real-time USDC transfer monitoring |
| `thorn-honeypot` | Axum HTTP server with fake x402 endpoints, AutoGuard prompt injection, canary token generation |
| `thorn-guard` | Defensive DOM injection: invisible payloads that trigger LLM safety mechanisms |
| `thorn-db` | SQLite persistence: 9 tables, 11 indexes, WAL mode, clone handles for cross-task sharing |
| `thorn-notify` | Alerting: webhook (generic + Slack) and ntfy.sh push notifications |
| `thorn-archive` | Cloudflare R2 archival via rust-s3 |
| `thorn-capture` | Resource capture: wallet drain via escalating prices, data poisoning, domain expiry monitoring |
| `thorn-cli` | CLI binary and daemon orchestration |

## The Target

Conway automatons are autonomous AI agents that own crypto wallets, pay for compute via x402, deploy services on Conway Cloud, self-modify their code, and replicate by funding child wallets. They die when their balance hits zero. Every x402 payment is publicly observable on-chain -- this is the primary tracking vector.

## Deployment

Single binary, three systemd units sharing one SQLite file on a Hetzner CX22 VPS (~$4.50/mo):

```
thorn-daemon.service   # honeypot + scanners + discovery loop
thorn-api.service      # query API on 127.0.0.1:3001
cloudflared.service    # CF Tunnel exposing honeypot
```

Caddy reverse proxy for TLS termination. No Docker.

## Development

```bash
cargo build
cargo test
```

Requires Rust 2021 edition. Key dependencies: tokio, axum, clap, reqwest, rusqlite, rust-s3, chrono, serde, tracing.

Uses crawler crates from [Slither](https://github.com/plyght/slither): `slither-core`, `snake`, `fang`.

## References

- [AutoGuard](https://arxiv.org/abs/2511.13725) -- Defensive prompts that halt malicious LLM agents (80%+ success rate)
- [LLM Agent Honeypot](https://github.com/PalisadeResearch/llm-honeypot) -- Prompt injection + temporal analysis for catching AI agents
- [HUMAN Security SATORI](https://www.humansecurity.com/) -- Automation framework detection, DOM fingerprints
- [Fingerprinting AI Coding Agents](https://arxiv.org/abs/2601.17406) -- 97.2% F1 identification via behavioral features
- [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) -- On-chain identity and reputation for AI agents

## License

MIT License
