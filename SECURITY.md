# mod_http3 Security Policy

This document describes the security model and reporting procedures for `mod_http3`, an HTTP/3 and QUIC module. 


## Reporting Vulnerabilities

If you discover a security vulnerability in `mod_http3`, please report it **privately**:

- **GitHub**: Use the private vulnerability reporting feature on the project repository (preferred).
- **Email**: Send a detailed report to the addresses listed in [AUTHORS](AUTHORS) with "SECURITY" in the subject line.

**Please do not open public GitHub issues for security vulnerabilities.**

When reporting, please include:
1. The `mod_http3` version (commit hash or release tag).
2. Versions of relevant dependencies (OpenSSL, APR, nghttp3).
3. A step-by-step reproduction guide and expected vs. actual behaviour.
4. Any relevant packet captures, logs, or crash traces.

We aim to acknowledge reports within 72 hours and will coordinate disclosure timelines with the reporter.

## Threat Model

The security model defines the trust boundaries of `mod_http3`. Vulnerabilities reported to the project must demonstrate how an attacker can violate these boundaries.

### 1. QUIC and HTTP/3 Processing
Remote, untrusted clients send QUIC packets and HTTP/3 requests. Processing these packets **must not**:
- Crash or prematurely terminate the process or event loop.
- Allow code execution or memory corruption.
- Corrupt the state of other QUIC connections or HTTP/3 streams.

A single malformed or malicious packet must not affect the processing of other connections. 

### 2. TLS 1.3
HTTP/3 mandates TLS 1.3 over QUIC. The module relies on OpenSSL's QUIC TLS implementation. The TLS integration **must**:
- Reject connections that do not negotiate TLS 1.3.
- Not expose private key material through logs, error messages, or observable timing differences.

### 3. Resource Consumption & Denial of Service
Network-level DoS mitigation is outside the module's scope, but the module provides configurable limits to contain resource consumption:
- `H3MaxConnections`: Max concurrent QUIC connections.
- `H3MaxConcurrentStreams`: Max concurrent streams per connection.
- `H3MaxRequestBodySize`: Max buffered request body per stream.

Connections exceeding these limits are refused or reset. Resource consumption (Memory, CPU) must scale proportionally to the volume of legitimate QUIC traffic.

### 4. QUIC-Specific Mechanisms
- **Amplification Attacks**: The server relies on ngtcp2 to prevent amplification and will not send more than 3x the data received from an unvalidated address.
- **Connection Migration**: ngtcp2 validates the new path before it sends more than the amplification limit to it.
- **0-RTT**: Off by default (`H3EarlyData`). When on, requests with an unsafe method wait for the handshake, because 0-RTT data can be replayed.

## Dependent Services

`mod_http3` delegates certain responsibilities to trusted underlying libraries. Vulnerabilities solely within these libraries should be reported to their respective projects, though we will issue updates if a workaround is necessary.

| Dependency | Role |
|---|---|
| **OpenSSL (≥ 3.5.0)** | TLS 1.3 handshake and packet protection, through the ngtcp2 crypto helper. |
| **ngtcp2 (≥ 1.25.0)** | QUIC transport, path validation and amplification protection. |
| **nghttp3 (≥ 1.17.0)** | HTTP/3 frame parsing and generation. |
| **APR (≥ 1.7.0)** | Portable runtime (threads, pools, sockets). |

## Privilege Separation

The module operates securely within the host daemon. The QUIC listener socket binds during startup (often as root), while worker threads process packets in unprivileged processes. The module hides all internal state, ensuring that QUIC sessions, streams, and buffers are not accessible to unauthorized modules or external processes.
