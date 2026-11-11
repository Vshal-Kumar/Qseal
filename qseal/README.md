# QSEAL: Production Operations & Architectural Manual
## Quantum-Secure Enterprise Access & Link — Headless Networking Engine

QSEAL is an independent, production-grade secure networking platform and daemon implemented in standard C11. It provides post-quantum and hybrid cryptographic network tunnels directly over raw POSIX UDP sockets across the public Internet.

QSEAL operates **100% autonomously in the terminal** without dependencies on Tailscale, WireGuard, OpenVPN, third-party coordination servers, or graphical interfaces. It features an interactive CLI setup wizard, headless systemd service automation, structured configuration files, and direct public-IP WAN communication.

---

## Table of Contents

1. [⚡ Quickstart: Step-by-Step Server & Client Deployment](#-quickstart-step-by-step-server--client-deployment)
2. [Global Public-IP Direct WAN Communication](#1-global-public-ip-direct-wan-communication)
   - [Architectural Topology](#architectural-topology)
   - [Bind Address (`0.0.0.0`) vs Advertised Public Endpoint](#bind-address-0000-vs-advertised-public-endpoint)
   - [Router Port Forwarding & Cloud Firewall Configuration](#router-port-forwarding--cloud-firewall-configuration)
   - [NAT Traversal & Continuous Keepalive Heartbeats](#nat-traversal--continuous-keepalive-heartbeats)
3. [Cryptographic Profiles & Technical Specifications](#2-cryptographic-profiles--technical-specifications)
   - [Profile A: Hybrid Mode (X25519 + ML-KEM-768)](#profile-a-hybrid-mode-recommended-enterprise)
   - [Profile B: Pure Post-Quantum Mode (NIST FIPS 203/204)](#profile-b-pure-post-quantum-mode-nist-fips-203204)
   - [Authenticated Negotiation & Downgrade Attack Prevention](#authenticated-negotiation--downgrade-attack-prevention)
4. [Terminal-Based Setup & Configuration](#3-terminal-based-setup--configuration)
   - [Interactive Terminal Setup Wizard (`qseal setup`)](#interactive-terminal-setup-wizard-qseal-setup)
   - [Unattended / Automated Provisioning (`qseal init`)](#unattended--automated-provisioning-qseal-init)
   - [Configuration File Schema (`qseal.json`)](#configuration-file-schema-qsealjson)
   - [Configuration Validation & Secret Redaction](#configuration-validation--secret-redaction)
5. [Server & Client Terminal Operations](#4-server--client-terminal-operations)
   - [Starting the Headless Server Daemon](#starting-the-headless-server-daemon)
   - [Connecting the Interactive Client Shell](#connecting-the-interactive-client-shell)
   - [Single-Shot Scripted Telemetry Delivery](#single-shot-scripted-telemetry-delivery)
   - [Client-to-Client Routed Messaging](#client-to-client-routed-messaging)
6. [Multi-Architecture Debian Packaging & Direct Installation](#5-multi-architecture-debian-packaging--direct-installation)
7. [Systemd Service Management](#6-systemd-service-management)
8. [Device Identity, Key Storage & Trust Store](#7-device-identity-key-storage--trust-store)
9. [Platform Diagnostics, Health Checks & Benchmarking](#8-platform-diagnostics-health-checks--benchmarking)
10. [Troubleshooting & Error Code Dictionary](#9-troubleshooting--error-code-dictionary)

---

## ⚡ Quickstart: Step-by-Step Server & Client Deployment

Standard Default Port: **UDP `9877`** | Default Server Bind: **`0.0.0.0:9877`**

```text
┌────────────────────────┐                          ┌────────────────────────┐
│      QSEAL Client      │     Public Internet      │      QSEAL Server      │
│  Target: 203.0.113.10  ├─────────────────────────►│  Bind: 0.0.0.0:9877    │
│  Port: 9877 (UDP)      │       Encrypted UDP      │  Advertised:           │
│  Identity: ~/.config/  │    (Hybrid / Pure PQC)   │    203.0.113.10:9877   │
└────────────────────────┘                          └────────────────────────┘
```

---

### 🖥️ Machine A: QSEAL Server (Public Server / Cloud VM / Port-Forwarded Host)

#### Step 1: Install the Debian Package
```bash
sudo dpkg -i qseal-x86.deb || sudo apt-get install -f -y
```

#### Step 2: Run the Terminal Setup Wizard
```bash
qseal setup
```
- **Select Role**: Choose `1) Server`
- **Crypto Mode**: Select `1) Hybrid (X25519 + ML-KEM-768)` [Recommended] or `2) Pure PQC`
- **Bind Address**: Press `[Enter]` for `0.0.0.0` (listens on all network interfaces)
- **UDP Port**: Press `[Enter]` for default port `9877`
- **Advertised Public Endpoint**: Enter your public IP or DNS hostname (e.g., `203.0.113.10:9877`)
- **Device ID**: Auto-detected or custom hostname (e.g., `srv-enterprise-01`)
- Keys and configuration are generated automatically with `0600` permissions.

#### Step 3: Launch the Server in Terminal
```bash
qseal server start
```

**Terminal Output:**
```text
╔══════════════════════════════════════════════════════════════════════════════════╗
║                 QSEAL Secure Server (Post-Quantum & Hybrid)                     ║
╚══════════════════════════════════════════════════════════════════════════════════╝
  Status        : LISTENING
  Bind Address  : 0.0.0.0 (UDP)
  Port          : 9877
  Advertised    : 203.0.113.10:9877
  Crypto Mode   : hybrid
  Device ID     : srv-enterprise-01
  Fingerprint   : 2b338d18b79f459b31d8e129fca84e031...
  Key File      : /etc/qseal/srv-enterprise-01.key

[Ready] Waiting for incoming client connections over UDP... (Press Ctrl+C to stop)
```

---

### 💻 Machine B: QSEAL Client (Remote Laptop / Field Gateway / Edge Node)

#### Step 1: Install the Debian Package
```bash
# On an x86_64 Laptop / VM:
sudo dpkg -i qseal-x86.deb || sudo apt-get install -f -y

# On a Raspberry Pi 4 / 5 (ARM64):
sudo dpkg -i qseal-arm64.deb || sudo apt-get install -f -y

# On a Raspberry Pi 2 / 3 (ARM32 / armhf):
sudo dpkg -i qseal-arm32.deb || sudo apt-get install -f -y
```

#### Step 2: Run the Terminal Setup Wizard
```bash
qseal setup
```
- **Select Role**: Choose `2) Client`
- **Crypto Mode**: Select `1) Hybrid` (matching server) or `2) Pure PQC`
- **Target Server IP**: Enter the server's public IP address (e.g., `203.0.113.10`)
- **Target UDP Port**: Press `[Enter]` for default `9877`
- **Device ID**: Enter client identifier (e.g., `cli-remote-01`)

#### Step 3: Connect to the Server
```bash
qseal client connect
```
*(No manual arguments required; automatically reads target from active configuration)*

**Real-Time Interactive Terminal Shell:**
```text
╔══════════════════════════════════════════════════════════════════════════════════╗
║                 QSEAL Secure Client (Post-Quantum & Hybrid)                     ║
╚══════════════════════════════════════════════════════════════════════════════════╝
  Target Server : 203.0.113.10:9877 (UDP)
  Crypto Mode   : hybrid
  Device ID     : cli-remote-01
  Fingerprint   : 0b33ec027f31aa92160b7192fde33a901...

[*] Connecting to 203.0.113.10:9877 over UDP...
[✓] Post-Quantum Handshake Established! Mutual Authentication Verified.
[✓] Encrypted Session Active. Session ID: 0x98124bcf8311aa01 (Latency: 2.15 ms)

╔═══════════════════════════════════════════════════════════════╗
║             QSEAL INTERACTIVE SECURE CHAT                    ║
║ Type messages to send encrypted over UDP. Type /quit to exit.  ║
║ Commands: /status, /metrics, /ping, /to <target> <msg>, /quit ║
╚═══════════════════════════════════════════════════════════════╝

qseal> Hello Server! Authenticated over public WAN.
[YOU → SERVER] Hello Server! Authenticated over public WAN. (Encrypted: 44 bytes)

[SERVER → YOU] Welcome cli-remote-01. Session verified.
qseal> /metrics
=========================================================
               QSEAL METRICS & HEALTH               
=========================================================
 Packets Transmitted (TX)   : 5 packets (4820 bytes)
 Packets Received (RX)      : 4 packets (2340 bytes)
 Handshake Latency          : 2.15 ms
 Session Uptime             : 28 seconds
=========================================================
qseal> /quit
[INFO] Disconnected from server
```

---

## 1. Global Public-IP Direct WAN Communication

QSEAL operates natively across wide-area networks (WAN) without requiring VPN concentrators, overlay mesh software, or third-party proxies.

### Architectural Topology

```text
                  +-----------------------------------+
                  |         PUBLIC INTERNET           |
                  +-----------------+-----------------+
                                    ▲
                         UDP Traffic│Port 9877
                                    ▼
       +---------------------------------------------------------+
       |                  QSEAL SERVER (0.0.0.0:9877)            |
       |  Advertised Endpoint: 203.0.113.10:9877                 |
       |  Manages concurrent client tunnels, replay windows      |
       +----------------------------+----------------------------+
                                    ▲
                 +------------------+------------------+
                 │                                     │
                 ▼ UDP Encrypted                       ▼ UDP Encrypted
      +----------------------+              +----------------------+
      |     QSEAL CLIENT 1   |              |     QSEAL CLIENT 2   |
      | Behind Home NAT      |              | Behind LTE / CGNAT   |
      | Endpoint: Dynamic    |              | Endpoint: Dynamic    |
      +----------------------+              +----------------------+
                 │                                     ▲
                 └─────────── Routed P2P ──────────────┘
                         (via Server /to cli-2)
```

---

### Bind Address (`0.0.0.0`) vs Advertised Public Endpoint

To prevent connectivity issues common in multihomed hosts and cloud environments:

- **`bind_address`**: The local IP address passed to the POSIX `bind()` system call. Setting `bind_address: "0.0.0.0"` instructs the Linux kernel to accept incoming UDP datagrams on port `9877` across **all active network interfaces** (Ethernet, Wi-Fi, cloud private VPC).
- **`advertised_endpoint`**: The publicly routable IP address or FQDN distributed to remote clients (e.g., `203.0.113.10:9877` or `vpn.enterprise.com:9877`).

In cloud instances (AWS EC2, Google Cloud Compute, Azure VMs), the operating system interface typically holds a private IP (e.g., `10.0.0.4`), while the cloud provider assigns an external Elastic/Public IP (`203.0.113.10`). Binding to `0.0.0.0` ensures the daemon receives packets forwarded from the cloud gateway.

---

### Router Port Forwarding & Cloud Firewall Configuration

#### 1. On-Premises / Home / Office Servers (Behind NAT Router)
If your server is connected to a local router with a private IP (`192.168.1.x`):
1. Open your router administration console (typically `192.168.1.1` or `192.168.0.1`).
2. Navigate to **Port Forwarding / Virtual Server / NAT Rules**.
3. Create a rule forwarding incoming traffic:
   - **Protocol**: `UDP`
   - **External Port**: `9877`
   - **Internal IP**: Local IP of the server host (e.g., `192.168.1.50`)
   - **Internal Port**: `9877`

#### 2. Cloud Firewalls & Security Groups
Ensure the cloud virtual firewall permits inbound UDP traffic on port `9877`:
- **AWS EC2 Security Group**: Add Inbound Rule `Custom UDP | Port 9877 | Source 0.0.0.0/0`.
- **GCP VPC Firewall**: Add rule `Allow | Protocols and ports: udp:9877 | Source IPv4 ranges: 0.0.0.0/0`.
- **Azure Network Security Group**: Add Inbound security rule `Source: Any | Protocol: UDP | Destination port ranges: 9877 | Action: Allow`.

#### 3. Host Firewall (UFW / iptables)
```bash
# Allow inbound UDP on port 9877 via UFW:
sudo ufw allow 9877/udp

# Or via iptables:
sudo iptables -A INPUT -p udp --dport 9877 -j ACCEPT
```

---

### NAT Traversal & Continuous Keepalive Heartbeats

- **Stateful NAT Mapping**: Remote clients behind residential NAT or mobile networks initiate outbound UDP packets to the server's public IP. Routers record an ephemeral port mapping in their state table.
- **Heartbeat Watchdog**: QSEAL clients automatically transmit periodic heartbeat datagrams (every 15 seconds) to the server. This prevents router connection tracking entries from expiring and keeps bidirectional communication open.
- **Session Watchdog**: The server monitors active sessions and cleanses session state if no traffic is received within `session_timeout_sec` (default: 60s).

---

## 2. Cryptographic Profiles & Technical Specifications

QSEAL enforces two standardized cryptographic operational profiles:

| Specification Parameter | Profile A: Hybrid Mode | Profile B: Pure PQC Mode |
| :--- | :--- | :--- |
| **Profile Identifier** | `profile-hybrid-1` | `profile-pqc-1` |
| **Recommended Use** | Production Enterprise WAN | High-Assurance / Pure Post-Quantum |
| **Classical Key Agreement** | X25519 ECDH (RFC 7748, 32-byte key) | *None (Zero classical mechanism)* |
| **Post-Quantum KEM** | ML-KEM-768 (NIST FIPS 203, Kyber768) | ML-KEM-768 (NIST FIPS 203, Kyber768) |
| **Digital Signatures** | Ed25519 (RFC 8032) + ML-DSA-65 (FIPS 204) | ML-DSA-65 (NIST FIPS 204, Dilithium3) |
| **Symmetric AEAD** | ChaCha20-Poly1305 (RFC 8439, 256-bit) | ChaCha20-Poly1305 (RFC 8439, 256-bit) |
| **Key Derivation (KDF)** | Dual Combiner: HKDF-SHA-384 (RFC 5869) | Single KDF: HKDF-SHA-384 (RFC 5869) |
| **Security Assurance** | Category 3 Quantum + 128-bit Classical | Category 3 Quantum (192-bit Quantum Safe) |

---

### Profile A: Hybrid Mode (Recommended Enterprise)

Hybrid Mode couples classical elliptic-curve security with post-quantum lattice cryptography:
1. **Dual Key Exchange**: Both nodes generate ephemeral X25519 keypairs and ML-KEM-768 keypairs.
2. **Dual Shared Secrets**: Ephemeral secrets $SS_{classical}$ (32 bytes) and $SS_{pqc}$ (32 bytes) are established independently.
3. **HKDF Combiner**: The two independent secrets are concatenated and extracted with SHA-384:
   $$SS_{master} = \text{HKDF-Extract}(\text{salt}=\text{transcript}, \, SS_{classical} \mathbin{\Vert} SS_{pqc})$$
   $$(K_{tx}, K_{rx}) = \text{HKDF-Expand}(SS_{master}, \, \text{"QSEAL-v1-hybrid-keys"}, \, 64)$$
4. **Defense in Depth**: Even if a quantum computer breaks discrete logarithms in X25519, ML-KEM-768 preserves secrecy; conversely, any unanticipated algebraic weakness in lattices is protected by X25519.

---

### Profile B: Pure Post-Quantum Mode (NIST FIPS 203/204)

Pure Post-Quantum Mode relies strictly on NIST standardized lattice-based cryptography:
1. **Key Encapsulation**: ML-KEM-768 under NIST FIPS 203.
2. **Digital Authentication**: ML-DSA-65 under NIST FIPS 204.
3. **Symmetric Encryption**: ChaCha20-Poly1305 under RFC 8439.
4. **Zero Classical Dependency**: Complete immunity against Shor's algorithm.

---

### Authenticated Negotiation & Downgrade Attack Prevention

- In `PKT_CLIENT_HELLO`, the client sends its supported profile list.
- The server checks the requested profiles against its local policy (`allow_classical_fallback`, `require_quantum_resistance`).
- **Downgrade Attack Rejection**: The negotiated profile ID is cryptographically bound into the handshake transcript signed by the peer's private key. Any in-flight modification of proposed parameters causes signature verification to fail immediately.
- Silent downgrades to unauthenticated or classical-only ciphers are strictly prohibited.

---

## 3. Terminal-Based Setup & Configuration

### Interactive Terminal Setup Wizard (`qseal setup`)

Run the onboarding wizard on any terminal to configure network parameters and generate keys:

```bash
qseal setup
```

The wizard conducts an 8-step initialization process:
1. Probes hardware SIMD extensions (AVX2, AES-NI, NEON) and available RAM.
2. Solicits the device role (`Server` or `Client`).
3. Selects the cryptographic profile (`Hybrid`, `Pure PQC`, or `Adaptive`).
4. Configures local bind address (`0.0.0.0`) and UDP port (`9877`).
5. Configures the advertised public IP or remote target address.
6. Tests UDP socket binding on the selected port.
7. Generates private keys with strict `0600` permissions.
8. Writes atomic configuration to `/etc/qseal/qseal.json` (or `~/.config/qseal/qseal.json`).

---

### Unattended / Automated Provisioning (`qseal init`)

For non-interactive headless deployment (Cloud-Init, Ansible, Docker, Terraform):

```bash
# Initialize Server:
qseal server init \
  --config /etc/qseal/qseal.json \
  --port 9877 \
  --bind 0.0.0.0 \
  --advertised 203.0.113.10:9877 \
  --mode hybrid \
  --device-id srv-cloud-01

# Initialize Client:
qseal client init \
  --config /etc/qseal/qseal.json \
  --server 203.0.113.10 \
  --port 9877 \
  --mode hybrid \
  --device-id cli-field-01
```

---

### Configuration File Schema (`qseal.json`)

The active configuration file is located at `/etc/qseal/qseal.json` (or `~/.config/qseal/qseal.json`):

```json
{
  "version": 1,
  "role": "server",
  "mode": "hybrid",
  "profile_id": "profile-hybrid-1",
  "network": {
    "bind_address": "0.0.0.0",
    "advertised_endpoint": "203.0.113.10:9877",
    "server_address": "203.0.113.10",
    "server_host": "203.0.113.10",
    "port": 9877,
    "connect_timeout_ms": 5000,
    "reconnect_attempts": 5,
    "heartbeat_interval_sec": 15,
    "session_timeout_sec": 60,
    "allow_client_to_client": true
  },
  "identity": {
    "device_id": "srv-cloud-01",
    "private_key_path": "/etc/qseal/srv-cloud-01.key",
    "public_key_path": "/etc/qseal/srv-cloud-01.pub",
    "trust_store_path": "/etc/qseal/trust_store.txt",
    "require_client_auth": true
  },
  "policy": {
    "require_quantum_resistance": true,
    "require_quantum_auth": false,
    "require_dual_combiner": true,
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

### Configuration Validation & Secret Redaction

Validate configuration syntax, file permissions, and network settings:
```bash
qseal config validate --config /etc/qseal/qseal.json
```

Display current configuration with private keys and sensitive parameters automatically masked:
```bash
qseal config show --config /etc/qseal/qseal.json
```

---

## 4. Server & Client Terminal Operations

### Starting the Headless Server Daemon

```bash
# Start server using active configuration:
qseal server start

# Start server with explicit port and mode overrides:
qseal server start --port 9877 --mode hybrid --bind 0.0.0.0
```

### Connecting the Interactive Client Shell

```bash
# Connect using stored configuration (targets configured public IP):
qseal client connect

# Connect with explicit destination overrides:
qseal client connect 203.0.113.10 9877
qseal client connect --server 203.0.113.10 --port 9877 --mode hybrid
```

#### Interactive Commands within Client Shell:
- `/status` — Displays current encryption mode, session ID, and peer identity.
- `/metrics` — Displays throughput (Kbps), packet counts (TX/RX), and round-trip latency.
- `/ping` — Transmits an authenticated keepalive datagram to the server.
- `/to <id> <msg>` — Sends a routed message to another connected client peer.
- `/quit` — Gracefully terminates the session and zeroizes encryption keys.

---

### Single-Shot Scripted Telemetry Delivery

For automated scripts, cron jobs, and telemetry publishing:

```bash
qseal client connect 203.0.113.10 9877 --msg "SENSOR_TELEMETRY: temp=23.4C,status=OK"
```
The client establishes a quantum-safe session, transmits the encrypted payload, awaits acknowledgment, and cleanly disconnects.

---

### Client-to-Client Routed Messaging

Authenticated clients connected to the same server can communicate with each other through the server's routing engine:

```text
# Send message to client with Client ID 2:
qseal> /to 2 Hello Client 2 from Client 1!

# Send message to client by Device ID:
qseal> /to cli-field-02 Diagnostic check complete.

# Broadcast message to all connected clients:
qseal> /to all Broadcast: Server maintenance in 10 minutes.
```
The server authenticates the sender, decrypts the inbound frame, re-encrypts the payload using the destination peer's session key, and forwards it over UDP.

---

## 5. Multi-Architecture Debian Packaging & Direct Installation

### Available Standalone `.deb` Packages

| Package File | Target Architecture | Target Hardware | Direct Terminal Install Command |
| :--- | :---: | :--- | :--- |
| **`qseal-x86.deb`** | `amd64` | Intel / AMD 64-bit servers, desktops, cloud VMs | `sudo dpkg -i qseal-x86.deb` |
| **`qseal-arm64.deb`** | `arm64` | Raspberry Pi 4 / 5, NVIDIA Jetson, ARM64 servers | `sudo dpkg -i qseal-arm64.deb` |
| **`qseal-arm32.deb`** | `armhf` | Raspberry Pi 2 / 3 running 32-bit Raspbian/Debian | `sudo dpkg -i qseal-arm32.deb` |

### Building Debian Packages from Source

```bash
# Build all 3 Debian packages:
make package

# Output packages generated in:
ls -lh qseal/packaging/debian/*.deb
```

### Filesystem Layout After Installation

- `/usr/bin/qseal` — Stripped unified production binary.
- `/etc/qseal/qseal.json` — Default configuration conffile (preserved during package updates).
- `/etc/qseal/*.key` — Cryptographic identity keys (`0600` permissions).
- `/etc/qseal/trust_store.txt` — Known host public key fingerprints database.
- `/usr/lib/systemd/system/qseal-server.service` — Server systemd daemon unit.
- `/usr/lib/systemd/system/qseal-client.service` — Client systemd daemon unit.
- `/var/lib/qseal/` — State and persistent runtime directory (`0700` mode).
- `/var/log/qseal/` — Audit logs directory (`0750` mode).

---

## 6. Systemd Service Management

Manage QSEAL as an autonomous background daemon:

```bash
# 1. Enable and start Server at boot:
sudo systemctl daemon-reload
sudo systemctl enable --now qseal-server.service

# 2. Check Server Service Status:
sudo systemctl status qseal-server.service

# 3. View live journal logs:
sudo journalctl -u qseal-server.service -f

# 4. Enable and start Client Service:
sudo systemctl enable --now qseal-client.service
```

---

## 7. Device Identity, Key Storage & Trust Store

### Strict Key File Security
- Private keys are stored in separate `.key` files protected by POSIX `umask(0077)` and **strict `0600` permissions**.
- Keys are owned by root (system service) or the invoking user (`~/.config/qseal/`).
- Private key material is never written to log files or JSON configurations.
- Keys in memory are purged using `OPENSSL_cleanse()` upon process termination.

### Trust On First Use (TOFU) & Cryptographic Pinning
- Public keys are indexed by their SHA-256 fingerprint (64 hexadecimal characters).
- On initial connection, with `policy.allow_tofu: true`, the peer's public key fingerprint is stored in `/etc/qseal/trust_store.txt`.
- On subsequent connections, if the presented public key does not match the pinned fingerprint, the connection is instantly aborted with an authentication alert.

---

## 8. Platform Diagnostics, Health Checks & Benchmarking

### Terminal Platform Diagnostics
Verify CPU architecture, SIMD acceleration, memory availability, and UDP port state:

```bash
qseal diagnostics
```

**Output:**
```text
=================================================================================
                       QSEAL PLATFORM DIAGNOSTICS                            
=================================================================================
 [✓] CPU Architecture : x86_64 (AMD Ryzen 5, 12 cores)
 [✓] SIMD Acceleration: AVX2=YES, AES-NI=YES, NEON=NO
 [✓] System Memory    : 6140 MB available / 14817 MB total
 [✓] OpenSSL EVP      : AVAILABLE [PASS]
 [✓] liboqs Backends  : AVAILABLE [PASS]
 [✓] ML-KEM-768 KEX   : VERIFIED [PASS]
 [✓] ML-DSA-65 DSA    : VERIFIED [PASS]
 [✓] Port 9877 (UDP)  : AVAILABLE
=================================================================================
 Diagnostic Result: System is fully ready for Hybrid and Pure PQC modes.
=================================================================================
```

---

### Terminal Cryptographic Microbenchmarks
Measure real operations/sec and latency on the host hardware:

```bash
# Benchmark Hybrid Profile:
qseal benchmark --mode hybrid

# Benchmark Pure PQC Profile:
qseal benchmark --mode pqc
```

**Measured Microbenchmark Latencies:**
```text
=================================================================================
               QSEAL CRYPTOGRAPHIC BENCHMARK (hybrid)                           
               Iterations: 100 | Profile: Hybrid Quantum-Safe
=================================================================================
 1. KEX Keygen              :    0.074 ms/op ( 13548 ops/sec)
 2. KEX Encapsulation       :    0.131 ms/op (  7643 ops/sec)
 3. KEX Decapsulation       :    0.092 ms/op ( 10879 ops/sec)
 4. DSA Signature Generate  :    0.209 ms/op (  4788 ops/sec)
 5. DSA Signature Verify    :    0.155 ms/op (  6462 ops/sec)
 6. AEAD (1KB) Encrypt      :    0.001 ms/op (  6015 Mbps)
=================================================================================
```

---

## 9. Troubleshooting & Error Code Dictionary

| Error String | Code | Root Cause | Solution |
| :--- | :---: | :--- | :--- |
| `QSEAL_ERR_NETWORK` | -5 | UDP socket failed to bind or port already in use. | Verify if another instance is running: `ss -ulnp \| grep 9877`. Stop old instance or change port. |
| `QSEAL_ERR_TIMEOUT` | -7 | Target UDP port unreachable or server not started. | 1. Ensure server is running: `qseal server start`<br>2. Check firewall: `sudo ufw allow 9877/udp`<br>3. Verify router port forwarding forwards UDP 9877 to server. |
| `QSEAL_ERR_AUTH_FAILED` | -6 | Peer public key doesn't match pinned fingerprint. | Verify peer identity. If the peer key was legitimately rotated, update the fingerprint in `trust_store.txt`. |
| `QSEAL_ERR_PERM_DENIED` | -3 | Configuration or key directory unwritable. | Ensure key directory has mode `0700` and keys have mode `0600`. Non-root users automatically fall back to `~/.config/qseal/`. |
| `QSEAL_ERR_NO_COMPAT_PROFILE` | -11 | Client and server do not share a permitted profile. | Verify that client and server both specify `--mode hybrid` or both specify `--mode pqc`. |
| `QSEAL_ERR_REPLAY_DETECTED` | -13 | Packet sequence number outside 64-datagram window or duplicated. | Datagram was replayed or severely out of order; packet was dropped. Check for network loops. |

---

## 10. Automated Regression & Test Suites

```bash
# Run all automated test suites (unit tests, integration tests, security lab):
make test

# Run individual suites:
make test-qseal          # Core QSEAL C11 engine unit & integration tests
make test-hybrid         # Dual combiner & hybrid cryptographic tests
make test-pqc            # Pure post-quantum FIPS 203/204 tests
make test-security-lab   # 15 automated resilience & attack scenarios in terminal
```

---

## License

QSEAL is licensed under the [MIT License](LICENSE).
Post-quantum cryptographic primitives are provided under the liboqs Apache 2.0 / MIT license.
OpenSSL cryptographic engines are provided under the Apache 2.0 license.
