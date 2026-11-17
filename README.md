# OmniRS — Omni Rust Server

**OmniRS** is a modular server platform written in Rust. The repository is organized as a Cargo workspace: the main server integrates HTTP services, an administration interface, databases, TLS/SSL management, DNS, tunneling, VPN, and IKEv2 components.

> **Project status:** This README describes the source tree in the supplied archive. It does not imply that every protocol or roadmap item is production-ready. Check the current implementation and test results before exposing services to the public Internet.

## HTTPS, TLS, HTTP/3 and QUIC

OmniRS supports modern web protocols and secure connections:

- **HTTPS** — secure access to websites and APIs.
- **TLS** — encrypted connections using native Rust TLS libraries.
- **HTTP/3** — support for the modern HTTP protocol over QUIC.
- **QUIC** — a UDP-based transport protocol providing encryption and reduced connection latency.
- **HTTPS over IP addresses** — the ability to establish secure connections directly through a public IP address without requiring a domain name, provided a suitable IP address certificate is available.
- **Let's Encrypt** — automated certificate issuance and management for supported scenarios, including IP address certificates.

OmniRS is designed as a unified server platform combining a web server, TLS, HTTP/3, QUIC, reverse proxying, and VPN capabilities.

## Features present in the source tree

- **HTTP server and administration API** — Axum-based server, static administration assets, API routes, health and metrics endpoints.
- **TLS/SSL management** — separate `ssl` crate and integration with Rust TLS libraries.
- **Reverse proxy and protocol components** — proxy-related server code, HTTP/3/QUIC dependencies, WebSocket-related dependencies, and tunnel components.
- **DNS** — a separate DNS crate; the main server source documents a DNS-over-HTTPS endpoint.
- **VPN** — a separate `vpn` crate with WireGuard-oriented interface, UAPI, netlink, and database code.
- **IKEv2** — a separate `ikev2` crate. The current source identifies its implementation as an IKEv2 server using PSK authentication; additional authentication methods should be treated as work in progress until implemented and tested.
- **Database layer** — a separate `db` crate and SQLite database files included in the supplied archive.
- **Security and CORS** — separate `security` and `cors` crates.
- **Miraj and tunnels** — separate `miraj` and `tunnel` crates.
- **Module examples** — an example module and module template are included.

## Workspace layout

```text
OmniRS/
├── Cargo.toml              # Cargo workspace and shared dependencies
├── core/                   # Core utilities and cryptography
├── cors/                   # CORS component
├── db/                     # Database component and bundled database files
├── dns/                    # DNS component
├── ikev2/                  # IKEv2 implementation
├── miraj/                  # Miraj component
├── security/               # Security component
├── server/                 # Main server binary, API, installer and admin assets
│   └── static/admin/       # Administration UI JavaScript and CSS
├── ssl/                    # TLS/SSL management
├── tunnel/                 # Tunnel component
├── vpn/                    # VPN component
├── examples/               # Example module and module template
├── public/                 # Public web content
└── admin-data/              # Administration data directory
```

## Requirements

- A Rust toolchain compatible with the workspace manifest (`edition = "2024"`; the manifest specifies `rust-version = "1.100"`).
- Cargo.
- Linux is the primary target implied by the current server/VPN implementation. Some features require elevated privileges and system networking support.
- For VPN/IPsec operation, configure firewall rules, forwarding, and network interfaces carefully. Required permissions depend on the selected backend.

Install Rust using the official instructions: <https://www.rust-lang.org/tools/install>.

## Build

Run these commands from the repository root:

```bash
cargo check --workspace
cargo build --release -p omni-server
```

The main binary target is named `OmniRS`. After a successful release build, Cargo normally places it at:

```text
target/release/OmniRS
```

A successful build verifies compilation only; it does not confirm that TLS issuance, VPN handshakes, forwarding, NAT, or client Internet access work in a real deployment.

## Run

The exact runtime configuration depends on the current `server` implementation and its configuration file. Review the configuration defaults and startup logic in `server/src/main.rs` before starting the service.

For a local development run:

```bash
cargo run --release -p omni-server
```

Do not expose an unconfigured instance to the public Internet. Set administrator credentials/tokens, review bind addresses, TLS settings, firewall policy, and file permissions first.

## Administration interface and API

The administration frontend is under `server/static/admin/`. It is split into JavaScript files for areas such as the dashboard, DNS, SSL, proxy, VPN, database, settings, files, modules, and terminal.

The main server source documents these routes:

| Route | Purpose described in source |
|---|---|
| `/` | Administration login / admin page |
| `/terminal` | Web terminal |
| `/api/*` | Administration API; authentication uses `x-admin-token` or a cookie |
| `/proxy/*` | Reverse proxy |
| `/dns-query` | DNS-over-HTTPS |
| `/health` | Health endpoint |
| `/metrics` | Prometheus-style metrics endpoint |

Routes and authentication behavior may evolve; confirm the current handlers and configuration before integrating external clients.

## VPN and IKEv2

The workspace currently separates VPN and IKEv2 into `vpn/` and `ikev2/`.

- WireGuard-related functionality is in `vpn/`.
- The IKEv2 crate currently labels its server implementation as PSK-based.
- The planned VPN mode selector (`wireguard`, `xfrm`, `userspace`) and expanded IKEv2 authentication methods (MSCHAPv2, RSA, EAP-TLS) must not be assumed available until the relevant code and tests are present.
- Linux XFRM and userspace ESP need careful interoperability and packet-flow testing on a real host.

**Cryptography policy:** the project requirement is to avoid OpenSSL and use Rust-native TLS/cryptography libraries. Verify the resolved dependency graph and build configuration to ensure no prohibited OpenSSL dependency is introduced transitively.

## Module development

An example module template is available at `examples/module-template/`, including a `module.toml`, an administration JavaScript entry, and a Rust installer source file. Use it as a starting point, then inspect the server's module loading and build-generation logic to confirm the exact supported module contract.

## Data and deployment notes

- Back up database files before upgrades or schema changes.
- Do not commit real secrets, private keys, administrator tokens, or production certificates.
- Treat bundled database files as development/sample state unless their provenance and intended use have been confirmed.
- Run networking and authentication tests after each VPN/IPsec change.
- Keep logs and diagnostic output free of full session keys and other secrets in production.

## Current development focus

The next VPN development stage is to add a persistent VPN mode setting and administration control, derive CHILD_SA keys after IKE_AUTH, and incrementally implement and test XFRM, MSCHAPv2, RSA authentication, and EAP-TLS. The existing WireGuard and IKEv2-PSK paths are the baseline and should be preserved while expanding functionality.

## Contributing

1. Keep changes scoped to the relevant workspace crate.
2. Preserve module boundaries and shared interfaces.
3. Run `cargo fmt --all` and `cargo check --workspace`.
4. Add protocol-level and integration tests for networking and cryptographic changes.
5. Document platform requirements, configuration changes, and known limitations in the pull request.

## License

No license was inferred from the supplied source archive. Add a `LICENSE` file and update this section before publishing or accepting contributions under an open-source license.
