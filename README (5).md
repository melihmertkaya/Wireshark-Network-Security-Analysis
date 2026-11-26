# Lab 06 — TLS Traffic Analysis

## Objective
Inspect a real TLS handshake in Wireshark, compare client-advertised cryptographic options with the server-selected parameters, and evaluate the visibility of encrypted traffic from a network security and SOC perspective.

## Environment
- Windows workstation and Wireshark
- IPv6 connection; TCP client port `51163`, server port `443`
- Server name indication (SNI): `www.youtube.com`
- TCP stream index: `7` (observed in Lab 03); TLS stream index: `5` (observed in both Hello detail views)
- Evidence: four screenshots from the captured handshake. Original PCAP and session keys were not supplied.

## Methodology
Locate the TLS Client Hello and Server Hello messages, inspect the cipher suite list and TLS extensions, and compare the negotiated settings. Useful Wireshark display filters for the original capture:

```wireshark
tls.handshake.type == 1 || tls.handshake.type == 2
frame.number == 470
frame.number == 488
tcp.stream == 7 && (tls.handshake.type == 1 || tls.handshake.type == 2)
```

## Handshake correlation

| Field | Client Hello | Server Hello |
|---|---|---|
| Frame number | 470 | 488 |
| Handshake type | Client Hello (1) | Server Hello (2) |
| Frame length | 2029 bytes | 1294 bytes |
| TLS record content type | Handshake (22) | Handshake (22) |
| Legacy record version | TLS 1.0 (0x0301) | TLS 1.2 (0x0303) |
| Legacy handshake version | TLS 1.2 (0x0303) | TLS 1.2 (0x0303) |
| Supported versions extension | TLS 1.3, TLS 1.2 (as summarized by Wireshark) | TLS 1.3 (0x0304) |
| Cipher suites | 16 entries, including one GREASE value | TLS_AES_128_GCM_SHA256 (0x1301) |
| Key share | X25519MLKEM768, X25519 | X25519MLKEM768 |
| Session ID length | 32 bytes | 32 bytes |
| Handshake message length field | 1946 bytes | 1206 bytes |
| Extensions length | 1841 bytes | 1134 bytes |

The legacy version fields are compatibility values, not evidence of a TLS downgrade. The server's `supported_versions` extension explicitly selects TLS 1.3. The TLS stream index is distinct from the TCP stream index.

## Client Hello analysis

The client offers three TLS 1.3 cipher suites, among other legacy-suite options:

| Cipher suite | Identifier |
|---|---|
| TLS_AES_128_GCM_SHA256 | 0x1301 |
| TLS_AES_256_GCM_SHA384 | 0x1302 |
| TLS_CHACHA20_POLY1305_SHA256 | 0x1303 |

The 16 advertised entries include one reserved GREASE value (`0x6a6a`), so the list contains 15 actual cipher-suite entries. Advertising an older cipher suite does not establish its use in this connection.

Other visible extensions include supported groups, signature algorithms, ALPN, encrypted_client_hello, server_name and session_ticket. SNI exposes `www.youtube.com` in this captured Client Hello. The presence of an ECH extension alone does not prove ECH was successfully negotiated; ALPN selection was not inspected.

![Client Hello details](screenshots/client-hello.png)

![Advertised cipher suites](screenshots/cipher-suites.png)

![Client Hello extensions](screenshots/client-extensions.png)

## Server Hello analysis

The server selects **TLS 1.3**, **TLS_AES_128_GCM_SHA256** and the **X25519MLKEM768** key share. Compression method is null (0).

- AES-128-GCM provides authenticated encryption for TLS records.
- SHA-256 is used in the TLS 1.3 key schedule and handshake transcript hashing for this suite.
- X25519MLKEM768 combines classical X25519 and post-quantum ML-KEM-768 key establishment. Its selection is separate from the cipher suite selection.
- Wireshark also exposes a JA3S fingerprint for the Server Hello. This is a useful investigation pivot, not a unique identity or proof of malicious activity.

![Selected server parameters](screenshots/server-hello.png)

## Security implications
- Unlike the plaintext HTTP traffic examined in Lab 05, TLS protects application data in transit after key establishment; certain handshake metadata can still be visible.
- TLS metadata (SNI, IP addresses, ports, negotiated versions, cipher suites and fingerprints) can support IDS/NDR/SOC investigations, baseline comparisons and triage.
- Legacy compatibility fields and advertised suites should not be mistaken for the negotiated TLS version or algorithm.
- A modern TLS configuration does not establish that the remote application, certificate or encrypted payload is benign.

## Skills practiced
- TLS handshake filtering and message correlation
- Cipher suite, SNI and TLS extension analysis
- Negotiated version and key-share interpretation
- Distinguishing TLS metadata from encrypted content
- Evidence-based encrypted traffic triage and technical reporting

## Limitations and conclusion
The evidence establishes the observed Hello exchange and selected TLS parameters. No certificate validation, decryption, application payload analysis or independent endpoint reputation check was performed in this lab. The original PCAP is unavailable, so the findings cannot be independently replayed from the repository. Device MAC addresses, capture-interface identifiers and IPv6 endpoint lines were masked in the published screenshots. The protocol details were otherwise preserved. This is a training exercise, not a confirmed security incident.
