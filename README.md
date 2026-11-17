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

## PHP, .htaccess and Reverse Proxy Support

OmniRS is designed to support common web hosting features, legacy PHP applications, and flexible proxy configurations.

- **PHP Support** — integration with PHP applications through PHP-FPM or FastCGI, enabling websites built with PHP, including WordPress and other popular CMS platforms.
- **.htaccess Support** — compatibility with Apache-style `.htaccess` configuration for directory-level URL rewriting, redirects, access rules, and other supported directives.
- **Reverse Proxy** — forwarding HTTP and HTTPS requests to backend applications and services.
- **Path-Based Proxying** — routing requests by URL prefix, such as `/api`, to different backend servers.
- **Virtual Hosts** — hosting multiple websites and applications on a single server.
- **Backend Load Balancing** — distributing requests across multiple backend servers.
- **URL Rewriting and Redirects** — configuring URL transformations and HTTP redirects.
- **Flexible Backend Integration** — connecting applications written in PHP, Rust, Node.js, Python, and other languages through supported protocols.

OmniRS aims to provide a unified alternative to traditional web server stacks by combining web serving, reverse proxying, TLS, HTTP/3, and QUIC in a single Rust-based platform.

**Note:** PHP execution requires a PHP runtime, such as PHP-FPM. `.htaccess` compatibility requires an implementation or translation layer for the supported directives; Apache's complete `.htaccess` functionality should not be assumed unless explicitly implemented.

## Advantages Over Nginx, Apache and OpenLiteSpeed

OmniRS is designed as a unified, Rust-based server platform that combines web serving, reverse proxying, modern network protocols, VPN functionality, and extensible modules in one ecosystem.

### Key Advantages

- **Unified Architecture** — web server, reverse proxy, TLS, DNS, VPN, and other server components within one platform.
- **Memory Safety** — written in Rust, reducing the risk of memory-related vulnerabilities common in unsafe code.
- **High Performance** — built on asynchronous Rust and Tokio for concurrent network workloads with minimal runtime overhead.
- **Modern Protocols** — designed to support HTTP/1.1, HTTP/2, HTTP/3, QUIC, TLS, and WebSockets.
- **IP-Based HTTPS** — support for secure connections through IP addresses when a suitable IP certificate is available.
- **Integrated VPN** — WireGuard and IKEv2 functionality within the same server ecosystem.
- **Flexible Reverse Proxy** — route requests to different backends by URL, integrate applications, and distribute traffic.
- **Modular Architecture** — extend functionality through independent components and modules.
- **Automation and Administration** — centralized configuration and a web-based administration interface.
- **Reduced Stack Complexity** — the potential to replace several separately managed services with one integrated platform.
- **Extensible Runtime** — planned WebAssembly-based modules for sandboxed application extensions.

### Comparison With Traditional Web Servers

| Feature | OmniRS | Nginx | Apache HTTP Server | OpenLiteSpeed |
|---|---|---|---|---|
| Implementation language | Rust | C | C | C/C++ |
| Memory-safety-oriented design | Yes | No | No | No |
| HTTP/1.1 and HTTP/2 | Designed to support | Yes | Yes | Yes |
| HTTP/3 and QUIC | Included in project scope | Supported in appropriate builds | Depends on version and configuration | Supported |
| HTTPS/TLS | Integrated TLS management | Yes | Yes | Yes |
| HTTPS using IP certificates | Supported when certificate flow permits | Certificate/configuration dependent | Certificate/configuration dependent | Certificate/configuration dependent |
| Reverse proxy | Integrated | Yes | Yes, with modules | Yes |
| PHP applications | Through PHP-FPM/FastCGI integration | Through PHP-FPM/FastCGI | Native FastCGI and other integrations | Integrated PHP support |
| `.htaccess` | Supported directives depend on implementation | No native `.htaccess` | Yes | Supported |
| VPN integration | Integrated project component | External service required | External service required | External service required |
| DNS component | Integrated project component | External service required | External service required | External service required |
| Web administration | Integrated project UI | Commonly external tools | Commonly external tools | WebAdmin |
| Modular extensions | Project modules; WebAssembly planned | Modules | Modules | Modules |

*This table describes the architectural goals and general characteristics of the products. Features marked as supported by OmniRS must be verified against the implementation and enabled build; the table does not imply that every planned feature is production-ready.*

## Database Connectivity and Protocol Support

OmniRS is intended to integrate with applications using popular database systems and their native client protocols.

- **PostgreSQL** — connectivity to PostgreSQL servers using the PostgreSQL wire protocol.
- **MySQL / MySQLi** — support for PHP applications using the MySQL protocol through MySQL-compatible database servers. MySQLi is a PHP database extension, not a separate network protocol.
- **SQLite** — embedded database support for applications that use local SQLite database files.
- **Database Integration** — connect backend applications to databases without requiring the web server itself to implement every database engine.
- **Multiple Database Backends** — allow different applications and modules to use different database systems.

### Database Compatibility

| Database | Protocol / Interface | Typical Use |
|---|---|---|
| PostgreSQL | PostgreSQL wire protocol | Relational databases and enterprise applications |
| MySQL | MySQL client/server protocol | Websites, CMS platforms, and web applications |
| MySQLi | PHP extension using the MySQL protocol | PHP applications and CMS integrations |
| SQLite | SQLite library/API and database files | Embedded applications and lightweight storage |

**Important:** Database connectivity can be provided by application runtimes, database drivers, and OmniRS modules. Native PostgreSQL protocol handling or direct MySQLi/SQLite integration inside the core server should only be claimed when implemented and tested.

OmniRS aims to combine the flexibility of traditional web servers with a memory-safe Rust architecture and an integrated server ecosystem, reducing operational complexity while supporting modern web applications and network services.

## Workspace layout

```text
OmniRS/                                      # Omni Rust Server project root
├── .cargo/                                  # Cargo build configuration
│   └── config.toml                           # Compiler and target platform settings
├── Cargo.toml                               # Main Cargo workspace manifest and shared dependencies
├── Cargo.lock                               # Locked Rust dependency versions
├── MAP.md                                   # Project architecture map and component relationships
├── MODULES.md                               # Module system documentation
├── ritual.sh                                # Installation, build, startup, and maintenance script
│
├── core/                                    # Core utilities and shared functionality
│   ├── Cargo.toml                           # Core component dependencies and configuration
│   └── src/
│       ├── lib.rs                           # Core library entry point and public interface
│       └── crypto.rs                        # Cryptographic functions and utilities
│
├── cors/                                    # Cross-Origin Resource Sharing (CORS) component
│   ├── Cargo.toml                           # CORS component dependencies
│   └── src/
│       └── lib.rs                           # CORS policy and request handling
│
├── db/                                      # Database access and storage
│   ├── Cargo.toml                           # Database component dependencies
│   ├── OmniDB                                 # Main SQLite database file
│   ├── OmniDB-shm                             # SQLite shared-memory file for OmniDB
│   ├── OmniDB-wal                             # SQLite write-ahead log for OmniDB
│   ├── OmniVPN                                # VPN database file
│   ├── OmniVPN-shm                            # SQLite shared-memory file for OmniVPN
│   ├── OmniVPN-wal                            # SQLite write-ahead log for OmniVPN
│   └── src/
│       ├── lib.rs                           # Main database library interface
│       └── dispatch.rs                      # Database operation dispatching
│
├── dns/                                     # DNS component
│   ├── Cargo.toml                           # DNS component dependencies
│   └── src/
│       └── lib.rs                           # DNS functionality and public interface
│
├── ikev2/                                   # IKEv2/IPsec VPN server
│   ├── Cargo.toml                           # IKEv2 component dependencies
│   └── src/
│       └── lib.rs                           # Main IKEv2 protocol implementation
│
├── miraj/                                   # Miraj component
│   ├── Cargo.toml                           # Miraj component dependencies
│   └── src/
│       └── lib.rs                           # Miraj functionality and public interface
│
├── security/                                # Security component
│   ├── Cargo.toml                           # Security component dependencies
│   └── src/
│       └── lib.rs                           # Security functionality and public interface
│
├── ssl/                                     # TLS/SSL and certificate management
│   ├── Cargo.toml                           # SSL component dependencies
│   └── src/
│       └── lib.rs                           # TLS/SSL management and certificate handling
│
├── tunnel/                                  # Tunneling and transport connections
│   ├── Cargo.toml                           # Tunnel component dependencies
│   └── src/
│       ├── lib.rs                           # Tunnel library entry point
│       ├── executor.rs                      # Tunnel operation execution
│       ├── protocols.rs                     # Supported transport protocols
│       ├── restrictions.rs                  # Access restrictions and rules
│       ├── server.rs                        # Tunnel server implementation
│       ├── somark.rs                        # SOMARK-related functionality
│       ├── tls_reloader.rs                  # TLS configuration reloading
│       └── transport.rs                     # Tunnel transport layer
│
├── vpn/                                     # VPN management and WireGuard integration
│   ├── Cargo.toml                           # VPN component dependencies
│   └── src/
│       ├── lib.rs                           # Main VPN interface and functionality
│       ├── db.rs                            # VPN database operations
│       ├── iface.rs                         # VPN network interface management
│       ├── netlink.rs                       # Linux Netlink communication
│       └── uapi.rs                          # WireGuard userspace API integration
│
├── server/                                  # Main OmniRS server application
│   ├── Cargo.toml                           # Server dependencies and binary configuration
│   ├── build.rs                             # Build-time resource preparation
│   │
│   ├── src/
│   │   ├── main.rs                          # Application entry point and server startup
│   │   ├── installer.rs                     # Installation and configuration logic
│   │   ├── modules.rs                       # Module loading and management
│   │   ├── omni_mw.rs                       # Server middleware
│   │   ├── static_assets.rs                 # Static asset handling
│   │   │
│   │   └── api/                             # Administration API
│   │       ├── mod.rs                       # API organization and registration
│   │       ├── auth.rs                      # Authentication and access control
│   │       ├── helpers.rs                   # Shared API helper functions
│   │       ├── sess.rs                      # Session management
│   │       │
│   │       └── handlers/                    # API request handlers
│   │           ├── mod.rs                   # Handler module registration
│   │           ├── cache.rs                 # Cache management operations
│   │           ├── dns_h.rs                 # DNS API handlers
│   │           ├── files.rs                 # File management API
│   │           ├── misc.rs                  # Miscellaneous API operations
│   │           ├── proxy.rs                 # Reverse proxy configuration and management
│   │           ├── settings.rs              # Server settings management
│   │           ├── system.rs                # System information and operations
│   │           └── ui.rs                    # Administration UI handlers
│   │
│   └── static/                              # Static web interface resources
│       ├── admin.html                       # Administration panel HTML
│       ├── admin/                           # Administration panel JavaScript and CSS
│       │   ├── app.js                       # Main administration interface logic
│       │   ├── dashboard.js                 # Dashboard and status monitoring
│       │   ├── db.js                        # Database management interface
│       │   ├── dns.js                       # DNS management interface
│       │   ├── files.js                     # File management interface
│       │   ├── modules.js                   # Module management interface
│       │   ├── proxy.js                     # Reverse proxy configuration interface
│       │   ├── settings.js                  # General server settings interface
│       │   ├── ssl.js                       # TLS/SSL and certificate management interface
│       │   ├── style.css                    # Administration panel styles
│       │   └── vpn.js                       # VPN management interface
│       │
│       ├── terminal.html                    # Web terminal HTML
│       └── terminal/                        # Web terminal components
│           ├── api.js                       # Terminal API communication
│           ├── app.js                       # Terminal initialization
│           ├── console.js                   # Console interface
│           ├── hack.js                      # Additional terminal interface effects
│           ├── leak.js                      # Additional interface logic
│           ├── state.js                     # Terminal state management
│           ├── style.css                    # Terminal styles
│           ├── ui.js                        # Terminal UI components
│           ├── utils.js                     # Shared terminal utilities
│           └── views.js                     # Terminal views and rendering
│
├── examples/                                # Example modules and templates
│   ├── example_module.zip                   # Example module archive
│   └── module-template/                     # Template for creating new modules
│       ├── module.toml                      # Module manifest and metadata
│       ├── admin/                           # Module administration assets
│       │   └── index.js                     # Module administration interface
│       └── src/
│           └── installer.rs                 # Rust module installer implementation
│
├── modules/                                 # Module lifecycle directories
│   ├── installed/                           # Installed modules
│   │   └── .keep                            # Keeps the directory in version control
│   ├── staging/                             # Temporary module installation files
│   │   └── .keep                            # Keeps the directory in version control
│   └── state/                               # Module state and metadata
│       └── .keep                            # Keeps the directory in version control
│
├── public/                                  # Public website files and web content
└── admin-data/                              # Administration data and runtime files
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
