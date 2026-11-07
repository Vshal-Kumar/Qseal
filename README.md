# QSEAL — Quantum-Secure Enterprise Access & Link

[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64%20%7C%20ARM64%20%7C%20ARM32-blue.svg)](#supported-architectures--hardware-hierarchy)
[![Cryptographic Profiles](https://img.shields.io/badge/Profiles-Hybrid%20%7C%20Pure%20PQC-success.svg)](#cryptographic-profiles--specifications)
[![FIPS Standards](https://img.shields.io/badge/Standards-NIST%20FIPS%20203%20%7C%20FIPS%20204-purple.svg)](#pure-post-quantum-profile-fips-203204)
[![Direct WAN](https://img.shields.io/badge/Transport-Native%20Direct%20UDP-orange.svg)](#global-public-ip-direct-connectivity)
[![Debian Packages](https://img.shields.io/badge/Packaging-Debian%20%28.deb%29-red.svg)](#debian-packaging--systemd-services)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**QSEAL (Quantum-Secure Enterprise Access & Link)** is an independent, production-grade secure communication and networking platform designed for high-assurance public Internet, enterprise access, and edge IoT connectivity. 

QSEAL operates **completely autonomously without dependencies on Tailscale, third-party VPN software, external coordination servers, or mandatory cloud relays**. It establishes, authenticates, encrypts, monitors, and terminates direct UDP sessions over the public Internet using NIST standardized post-quantum and hybrid cryptography.

---

## Table of Contents

- [Core Platform Capabilities](#core-platform-capabilities)
- [Cryptographic Profiles & Specifications](#cryptographic-profiles--specifications)
  - [Profile A: Hybrid Mode (Dual Classical + Post-Quantum)](#profile-a-hybrid-mode-dual-classical--post-quantum)
  - [Profile B: Pure Post-Quantum Mode (NIST FIPS 203/204)](#profile-b-pure-post-quantum-mode-nist-fips-203204)
  - [Authenticated Profile Negotiation & Downgrade Protection](#authenticated-profile-negotiation--downgrade-protection)
- [Global Public-IP Direct Connectivity](#global-public-ip-direct-connectivity)
  - [Bind Address vs Advertised Public Endpoint](#bind-address-vs-advertised-public-endpoint)
  - [NAT Traversal, Port Forwarding, and CGNAT Diagnostics](#nat-traversal-port-forwarding-and-cgnat-diagnostics)
- [Platform Architecture & Multi-Client Engine](#platform-architecture--multi-client-engine)
  - [Independent Server Implementation](#independent-server-implementation)
  - [Independent Client Implementation](#independent-client-implementation)
  - [Client-to-Client Routed Messaging](#client-to-client-routed-messaging)
  - [Memory Zeroization & Sliding Replay Window](#memory-zeroization--sliding-replay-window)
- [Quick Start & Setup Guide](#quick-start--setup-guide)
  - [Interactive Onboarding Wizard](#interactive-onboarding-wizard)
  - [Scripted & Non-Interactive Unattended Provisioning](#scripted--non-interactive-unattended-provisioning)
  - [Starting the Headless Server](#starting-the-headless-server)
  - [Connecting the Independent Client](#connecting-the-independent-client)
- [CLI Reference](#cli-reference)
- [Configuration Specification & Schemas](#configuration-specification--schemas)
- [Debian Packaging & Systemd Services](#debian-packaging--systemd-services)
- [Empirical Performance & Microbenchmark Results](#empirical-performance--microbenchmark-results)
- [Automated Verification & Test Suites](#automated-verification--test-suites)
- [Repository Organization & Hygiene](#repository-organization--hygiene)

---

## Core Platform Capabilities

- **100% Independent Networking**: Operates directly over raw POSIX UDP sockets on the public Internet. No Tailscale, WireGuard, OpenVPN, or centralized relays.
- **Strict Post-Quantum Cryptography**: Compliant with NIST FIPS 203 (ML-KEM-768) and NIST FIPS 204 (ML-DSA-65).
- **Hybrid Quantum-Safe Mode**: Combines classical X25519 ECDH and ML-KEM-768 key encapsulation via HKDF-SHA-384, providing dual-layer defense-in-depth against *Harvest Now, Decrypt Later* attacks.
- **Mutual Authentication**: Full mutual cryptographic authentication of server and client identities prior to session activation.
- **Direct WAN / Public IP Support**: Explicit separation of local bind address (`0.0.0.0`) and globally routable advertised public endpoint (`public_ip:port` or `fqdn:port`).
- **Concurrent Multi-Client Server**: Headless Linux daemon managing up to 64 concurrent client tunnels with individual replay windows, session timeouts, and heartbeats.
- **Client-to-Client Routed Communication**: Server-routed peer-to-peer messaging (`to:<target>:<msg>`) allowing authenticated clients to communicate through the server.
- **Automated Diagnostics**: Real-time network interface classification (Loopback, LAN, Private NAT RFC 1918, CGNAT RFC 6598, and Public Direct IP) with port binding tests.
- **Production Debian Packaging**: Generates standalone `.deb` packages for AMD64, ARM64, and ARM32 with strict `0700` and `0600` key permissions and Systemd units.
- **Zero Insecure Fallbacks**: No mock cryptographic loops, dummy signatures, or XOR decryptors. Insecure code has been completely removed.

---

## Cryptographic Profiles & Specifications

QSEAL enforces exactly two primary cryptographic operational profiles:

| Specification Parameter | Profile A: Hybrid Mode | Profile B: Pure PQC Mode |
| :--- | :--- | :--- |
| **Operational Designation** | `hybrid` (Recommended Enterprise Profile) | `pqc` (NIST High-Assurance Profile) |
| **Classical Key Agreement** | X25519 ECDH (RFC 7748, 32 bytes) | *None (Zero classical dependency)* |
| **Post-Quantum KEM** | ML-KEM-768 (NIST FIPS 203, Kyber768) | ML-KEM-768 (NIST FIPS 203, Kyber768) |
| **Public Key Size (KEM)** | 32 B (ECDH) + 1184 B (ML-KEM) = 1216 B | 1184 bytes |
| **Ciphertext Size (KEM)** | 32 B (ECDH) + 1088 B (ML-KEM) = 1120 B | 1088 bytes |
| **Digital Signature / Auth** | ML-DSA-65 (NIST FIPS 204) + Ed25519 (RFC 8032) | ML-DSA-65 (NIST FIPS 204, Dilithium3) |
| **Signature Size** | 64 B (Ed25519) + 3309 B (ML-DSA) = 3373 B | 3309 bytes |
| **Key Derivation (KDF)** | HKDF-SHA-384 (RFC 5869) Dual Combiner | HKDF-SHA-384 (RFC 5869) Single-Secret KDF |
| **Symmetric AEAD** | ChaCha20-Poly1305 (RFC 8439, 256-bit key) | ChaCha20-Poly1305 (RFC 8439, 256-bit key) |
| **Nonce & Tag Size** | 12-byte Nonce, 16-byte Poly1305 Auth Tag | 12-byte Nonce, 16-byte Poly1305 Auth Tag |
| **Security Level** | Category 3 Post-Quantum (192-bit) + 128-bit Classical | Category 3 Post-Quantum (192-bit Quantum Safe) |

---

### Profile A: Hybrid Mode (Dual Classical + Post-Quantum)

Hybrid Mode utilizes a dual-combiner architecture where session security requires breaking **both** the classical ECDH mechanism and the post-quantum lattice problem:
1. **Key Agreement**: Client and Server generate ephemeral X25519 keypairs ($pk_c, sk_c$) and ML-KEM-768 keypairs ($pk_q, sk_q$).
2. **Encapsulation**: Ephemeral shared secrets $SS_{classical} \in \{0,1\}^{32}$ and $SS_{pqc} \in \{0,1\}^{32}$ are established independently.
3. **HKDF Combiner**: The two independent secrets are mixed into a master session secret using HKDF-Extract and HKDF-Expand with SHA-384:
   $$\text{Combined Secret } SS_{master} = \text{HKDF-Extract}(\text{salt}=\text{transcript}, \, SS_{classical} \mathbin{\Vert} SS_{pqc})$$
   $$\text{Session Keys } (K_{tx}, K_{rx}) = \text{HKDF-Expand}(SS_{master}, \, \text{"QSEAL-v1-hybrid-keys"}, \, 64)$$
4. **Authentication**: Handshake transcripts are signed using dual ML-DSA-65 and Ed25519 credentials and pinned against the local trust store.

---

### Profile B: Pure Post-Quantum Mode (NIST FIPS 203/204)

Pure PQC Mode operates strictly using standardized lattice-based post-quantum cryptography:
1. **Module-Lattice KEM**: ML-KEM-768 parameter set under NIST FIPS 203.
2. **Module-Lattice DSA**: ML-DSA-65 parameter set under NIST FIPS 204.
3. **Session AEAD**: ChaCha20-Poly1305 authenticated symmetric encryption under RFC 8439.
4. **Zero Classical Secrets**: Eliminates elliptic curve vulnerabilities to Shor's algorithm.

---

### Authenticated Profile Negotiation & Downgrade Protection

- During the cryptographic handshake, the client presents its supported profile list in `PKT_CLIENT_HELLO`.
- The server evaluates the requested profiles against its administrator-configured policy (`server.json`).
- If no mutual post-quantum profile is permitted, the server terminates the handshake with `QSEAL_ERR_POLICY_REJECTED`.
- **Anti-Downgrade Invariant**: The platform **never silently downgrades** to unauthenticated or classical-only configurations. The negotiated parameters form part of the signed transcript, making MITM downgrade attacks mathematically detectable.

---

## Global Public-IP Direct Connectivity

QSEAL communicates directly across the public Internet via UDP. The default communication topology is:

$$\text{QSEAL Client} \xrightarrow{\quad\text{Public Internet (UDP)}\quad} \text{QSEAL Server}$$

```
+------------------------+                        +------------------------+
|      QSEAL CLIENT      |                        |      QSEAL SERVER      |
|                        |                        |                        |
|  Device: cli-1         |   Public Internet      |  Device: srv-1         |
|  Identity: 0600 Key    |  ------------------>   |  Identity: 0600 Key    |
|  Target: 203.0.113.10  |      UDP :9877         |  Bind: 0.0.0.0:9877    |
|  Mode: Hybrid / PQC    |                        |  Advertised: 203.0.113.10
+------------------------+                        +------------------------+
```

### Bind Address vs Advertised Public Endpoint

To ensure seamless operation in cloud environments, multi-homed servers, and containerized networks, QSEAL makes an explicit architectural distinction:
- **`bind_address`**: The local IP address on which the server socket binds (typically `0.0.0.0` to listen on all interfaces, or an explicit private IP like `10.0.0.4`).
- **`advertised_endpoint`**: The globally routable public IP address or DNS hostname (e.g. `203.0.113.10:9877` or `vpn.enterprise.com:9877`) distributed to remote clients.

Clients connect to `advertised_endpoint`, while the host daemon listens on `bind_address`.

---

### NAT Traversal, Port Forwarding, and CGNAT Diagnostics

QSEAL includes an integrated network categorization engine executed during onboarding (`qseal setup`) and runtime diagnostics (`qseal diagnostics`):

| Network Classification | Address Range | Connectivity Behavior & Administrator Action |
| :--- | :--- | :--- |
| **Public Direct IP** | Globally routable IPv4 / IPv6 | **Native Direct**: Inbound and outbound connections operate without translation. |
| **Private NAT** | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | **Port Forwarding Required**: Edge router must forward external UDP port `9877` to host's local IP. |
| **Carrier-Grade NAT (CGNAT)** | `100.64.0.0/10` (RFC 6598) | **Inbound Blocked**: Direct inbound connections cannot be hosted behind CGNAT. Server must use a VPS or static public IP. |
| **Loopback** | `127.0.0.1`, `::1` | **Local IPC Only**: Suitable for unit testing and local service integration. |

---

## Platform Architecture & Multi-Client Engine

```
QHack / QSEAL Platform Root
├── qseal/                  # Authoritative QSEAL Core Engine & Production Binaries
│   ├── bin/
│   │   ├── qseal                # Primary Unified Multi-Tool Executable
│   │   └── qseal           # Compatibility Symlink
│   ├── include/qseal/      # Public C API Headers (server, client, config, crypto)
│   ├── src/
│   │   ├── server/server.c      # Multi-Client UDP Engine with sliding replay & routing
│   │   ├── client/client.c      # Bidirectional Client Engine with interactive console
│   │   ├── cli/cli.c            # Command-Line Dispatcher & Network Diagnostics
│   │   ├── config/config.c      # Atomic JSON Parser, Validator, and Serializer
│   │   ├── setup/setup_wizard.c # Interactive & Scriptable Onboarding System
│   │   └── identity/identity.c  # Persistent Cryptographic Key Management (0600 / 0700)
│   └── packaging/
│       ├── debian/build_deb.sh  # Multi-Architecture Debian Packaging Engine
│       └── systemd/             # Production Systemd Services (qseal-server, qseal-client)
│
├── hybrid/                      # Hybrid Combiner Subsystem (libhybrid)
├── pqc/                         # NIST FIPS 203/204 Subsystem (ML-KEM, ML-DSA)
├── security_lab/                # Automated Security & Safety Verification Test Suite
├── liboqs/                      # Open Quantum Safe Post-Quantum Cryptography Library
└── liburing_local/              # Linux io_uring Asynchronous I/O Headers
```

### Independent Server Implementation

The QSEAL Server (`qseal server start`) runs headlessly as a daemon:
- Socket binding with `SO_REUSEADDR` and non-blocking POSIX `poll()` event multiplexing.
- Multi-client session table tracking up to 64 active peers concurrently.
- Heartbeat watchdog scanning active sessions every 5 seconds; drops inactive peers exceeding `session_timeout_sec` (default 60s).
- Session zeroization on teardown via `OPENSSL_cleanse`.

### Independent Client Implementation

The QSEAL Client (`qseal client connect`) functions as a command-line tool or background worker:
- Initiates ephemeral handshake with target server over UDP.
- Enforces mutual authentication and pins server identity via Trust-On-First-Use (TOFU) or pre-shared trust store.
- Supports both interactive full-duplex messaging and single-shot scripted delivery (`--msg "<text>"`).
- Sends periodic heartbeats (every 3 seconds) to maintain NAT state and keep firewall UDP states alive.

### Client-to-Client Routed Messaging

QSEAL servers support authenticated peer-to-peer message routing:
- Clients can address peers by numeric Client ID: `/to <id> <message>` (wire format: `to:<id>:<message>`).
- Clients can address peers by device identifier: `/to <device_id> <message>` (e.g. `to:cli-2:Hello`).
- Clients can broadcast to all connected peers: `/to all <message>`.
- The server verifies session establishment, enforces isolation, and re-encrypts the routed payload to the destination peer's unique session key.

### Memory Zeroization & Sliding Replay Window

- **Replay Protection**: Each session maintains an independent 64-packet bitmask window (`replay_bitmap`). Out-of-order packets within the window are checked and marked; packets older than the window or previously marked are dropped immediately.
- **Memory Zeroization**: Symmetric keys (`rx_key`, `tx_key`), shared secrets (`ss`), and private credentials are cleansed with `OPENSSL_cleanse` upon session closure.

---

## Quick Start & Setup Guide

### Interactive Onboarding Wizard

Run the interactive setup wizard on any Linux machine:

```bash
qseal setup
```

The wizard guides you through:
1. Hardware architecture and SIMD capability detection (AVX2, AES-NI, NEON).
2. Node role selection (`Server` or `Client`).
3. Cryptographic profile selection (`Hybrid Mode` [Recommended] or `Pure PQC Mode`).
4. Network endpoint configuration (Bind IP, UDP Port, Advertised Public Endpoint).
5. Pre-binding socket check to verify UDP port availability.
6. Identity generation with strict file permissions (`0600` private key, `0700` directory).

---

### Scripted & Non-Interactive Unattended Provisioning

For automated deployments (Cloud-Init, Ansible, Docker):

```bash
# 1. Initialize Headless Server:
qseal server init --config /etc/qseal/server.json \
                  --port 9877 \
                  --bind 0.0.0.0 \
                  --advertised 203.0.113.10:9877 \
                  --mode hybrid \
                  --device-id srv-prod-1

# 2. Initialize Remote Client:
qseal client init --config /etc/qseal/client.json \
                  --server 203.0.113.10 \
                  --port 9877 \
                  --mode hybrid \
                  --device-id cli-node-1
```

---

### Starting the Headless Server

```bash
# Start server using active configuration:
qseal server start --config /etc/qseal/server.json

# Or run with command-line overrides:
qseal server start --port 9877 --mode hybrid
```

---

### Connecting the Independent Client

```bash
# Start interactive encrypted chat session:
qseal client connect 203.0.113.10 9877 --config /etc/qseal/client.json

# Or send a single automated telemetry payload and exit:
qseal client connect 203.0.113.10 9877 --msg "Telemetry payload: System OK"
```

---

## CLI Reference

```text
Usage: qseal <command> [options]

Platform Management Commands:
  setup                     Run guided interactive onboarding setup wizard
  detect                    Detect hardware, CPU SIMD features, memory, and crypto backends
  diagnostics               Run comprehensive network, port, NAT, and crypto diagnostics
  status                    Display service configuration and running state
  benchmark                 Run cryptographic microbenchmarks (Hybrid & Pure PQC)

Server Commands:
  server [start] [port]     Launch independent QSEAL UDP server (default: 0.0.0.0:9877)
  server init               Initialize server identity keys and default configuration

Client Commands:
  client [connect] [host]   Establish secure quantum-safe tunnel to server
  client init               Initialize client identity keys and default configuration

Configuration & Profiles:
  config validate           Validate syntax, permissions, and network settings of config
  config show               Display active configuration with secret redaction
  profiles list             List registered cryptographic profiles (Hybrid, PQC)
  profiles check            Check hardware and library compatibility for each profile

Global Options:
  --server <ip/host>        Target server IP address or hostname
  --port <port>             Target or bind UDP port (default: 9877)
  --bind <ip>               Server bind address (default: 0.0.0.0)
  --advertised <ip/host>    Server globally advertised public endpoint
  --device-id <id>          Set local node identifier
  --mode <hybrid|pqc>       Enforce cryptographic mode (default: hybrid)
  --config <path>           Specify explicit configuration file path
  --msg <text>              Send single message and exit (non-interactive)
  --non-interactive         Run setup non-interactively for automated deployments
  --version, -v             Display version information
  --help, -h                Display this help message
```

---

## Configuration Specification & Schemas

QSEAL configurations are stored in JSON format at `/etc/qseal/qseal.json` (or `~/.config/qseal/qseal.json` for non-root users):

```json
{
  "version": 1,
  "role": "server",
  "mode": "hybrid",
  "profile_id": "profile-hybrid-1",
  "network": {
    "bind_address": "0.0.0.0",
    "advertised_endpoint": "203.0.113.10:9877",
    "server_address": "127.0.0.1",
    "server_host": "127.0.0.1",
    "port": 9877,
    "connect_timeout_ms": 5000,
    "reconnect_attempts": 5,
    "heartbeat_interval_sec": 15,
    "session_timeout_sec": 60,
    "allow_client_to_client": true
  },
  "identity": {
    "device_id": "srv-prod-1",
    "private_key_path": "/etc/qseal/srv-prod-1.key",
    "public_key_path": "/etc/qseal/srv-prod-1.pub",
    "trust_store_path": "/etc/qseal/trust_store.txt",
    "require_client_auth": true
  },
  "policy": {
    "require_quantum_resistance": true,
    "require_quantum_auth": false,
    "require_dual_combiner": false,
    "allow_classical_fallback": false,
    "require_fips_algorithms": true,
    "max_acceptable_latency_ms": 500,
    "max_memory_budget_mb": 256,
    "allow_tofu": true,
    "preference": "balanced"
  },
  "resources": {
    "max_concurrent_sessions": 64,
    "rx_buffer_kb": 256,
    "worker_threads": 4
  },
  "logging": {
    "level": "info",
    "file": ""
  },
  "auto_start_service": false
}
```

---

## Debian Packaging & Systemd Services

QSEAL builds native `.deb` packages for production Debian, Ubuntu, Linux Mint, and Raspberry Pi OS distributions:

```bash
# Build all 3 Debian packages:
make package
```

Generated packages in `qseal/packaging/debian/`:
- `qseal-amd64.deb`: 64-bit x86 servers, desktops, cloud VMs.
- `qseal-arm64.deb`: Raspberry Pi 4/5, NVIDIA Jetson, AWS Graviton.
- `qseal-arm32.deb`: Raspberry Pi 2/3 running 32-bit Raspbian (`armhf`).

### Installation & Security Hardening

```bash
# Install package:
sudo dpkg -i qseal/packaging/debian/qseal-amd64.deb

# Package post-installation automatically sets strict permissions:
# - /etc/qseal      -> 0700 (Owner: root)
# - /var/lib/qseal  -> 0700 (Owner: root)
# - /var/log/qseal  -> 0750 (Owner: root)
# - *.key           -> 0600 (Owner: root)
```

### Systemd Service Management

```bash
# Start Server Service:
sudo systemctl enable --now qseal-server

# Check Server Status:
sudo systemctl status qseal-server

# Start Client Service:
sudo systemctl enable --now qseal-client
```

---

## Empirical Performance & Microbenchmark Results

Benchmarked on host hardware: AMD Ryzen 5 5500U (12 cores, AVX2 enabled, Linux 6.8):

### 1. Cryptographic Primitive Performance

| Operation | Algorithm | Mean Latency | Throughput | Wire Size |
| :--- | :--- | :---: | :---: | :---: |
| **KEX Keygen (Hybrid)** | X25519 + ML-KEM-768 | **0.074 ms** | 13,548 ops/sec | 1,216 bytes |
| **KEX Encapsulation (Hybrid)** | X25519 + ML-KEM-768 | **0.131 ms** | 7,643 ops/sec | 1,120 bytes |
| **KEX Decapsulation (Hybrid)** | X25519 + ML-KEM-768 | **0.092 ms** | 10,879 ops/sec | 64 bytes |
| **KEX Keygen (Pure PQC)** | ML-KEM-768 (FIPS 203) | **0.036 ms** | 27,884 ops/sec | 1,184 bytes |
| **KEX Encapsulation (Pure PQC)** | ML-KEM-768 (FIPS 203) | **0.019 ms** | 53,661 ops/sec | 1,088 bytes |
| **KEX Decapsulation (Pure PQC)** | ML-KEM-768 (FIPS 203) | **0.022 ms** | 46,071 ops/sec | 32 bytes |
| **DSA Sign (Pure PQC)** | ML-DSA-65 (FIPS 204) | **0.130 ms** | 7,671 ops/sec | 3,309 bytes |
| **DSA Verify (Pure PQC)** | ML-DSA-65 (FIPS 204) | **0.046 ms** | 21,596 ops/sec | 3,309 bytes |
| **AEAD Encrypt (1 KB)** | ChaCha20-Poly1305 | **0.001 ms** | **6,015 Mbps (6.0 Gbps)** | 1,024 bytes |

### 2. Live Client-Server Handshake Latencies

| Mode | Measured End-to-End Handshake Latency | Memory Footprint (RSS) |
| :--- | :---: | :---: |
| **Pure PQC Mode** (ML-KEM-768 + ML-DSA-65) | **2.31 ms** | 8.5 MB |
| **Hybrid Mode** (X25519 + ML-KEM-768) | **3.73 ms** | 8.7 MB |
| **Legacy Baseline (Pre-Quantum Reference)** | **3.34 ms** | 8.4 MB |

---

## Automated Verification & Test Suites

QSEAL includes a comprehensive hierarchy of automated regression, safety, and integration test suites:

```bash
# 1. Run QSEAL Core Engine Unit Tests:
make -C qseal unit_tests

# 2. Run Real UDP Client-Server Integration Tests:
make -C qseal integration_tests

# 3. Run Security & Safety Guard Allowlist Verification:
make -C security_lab test

# 4. Run All Subsystem Regression Tests:
make test
```

All test suites execute against live cryptographic primitives and real network sockets without mock stubs.

---

## Repository Organization & Hygiene

- No build artifacts or private keys (`*.key`, `*.pem`, `*.o`, `*.deb`) are tracked in source control.
- All temporary integration test files write strictly to `/tmp/`.
- Private cryptographic keys created by QSEAL are locked with `chmod 0600` at creation time.
- Fully compatible with standard Linux distribution packaging standards.

---

## License

QSEAL is licensed under the [MIT License](LICENSE).
Open Quantum Safe primitives are provided under the liboqs Apache 2.0 / MIT license.
OpenSSL EVP engines are provided under the Apache 2.0 license.
