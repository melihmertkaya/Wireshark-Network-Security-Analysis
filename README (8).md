# Wireshark — Network & Security Analysis

A hands-on network traffic analysis portfolio covering packet inspection, protocol behavior, connectivity troubleshooting, encrypted traffic metadata, and network traffic profiling.

**Author:** Melih Mert Kaya  
**Environment:** Windows · Wireshark · Wi-Fi · IPv4 / IPv6  
**Project status:** 8 documented labs completed · 16 evidence screenshots

## Project overview

This project analyzes real traffic captured on a personal network. It progresses from local address resolution and connectivity testing to TCP connection behavior, DNS, plaintext HTTP, TLS negotiation, TCP recovery mechanisms, and aggregate network statistics. Each lab documents the methodology, observed packet evidence, technical findings, security implications, and limitations.

The objective is to develop practical packet-analysis skills relevant to entry-level Network Engineering, Network Security, NOC and SOC roles. The project is a learning portfolio, not a production network assessment or a confirmed incident investigation.

## Lab index

| Lab | Topic | Main finding |
| --- | --- | --- |
| 01 | [ARP & MAC Address Analysis](Lab-01-ARP-Analysis/README.md) | Matched broadcast ARP request and unicast reply; IPv4-to-MAC resolution. |
| 02 | [ICMP & Network Troubleshooting](Lab-02-ICMP-Analysis/README.md) | Four matching ping replies; mean observed RTT of 10.46 ms. |
| 03 | [TCP Three-Way Handshake & Connection Lifecycle](Lab-03-TCP-Handshake/README.md) | Completed SYN / SYN-ACK / ACK exchange and FIN-based termination. |
| 04 | [DNS Traffic Analysis](Lab-04-DNS-Analysis/README.md) | DNS transaction correlation, multiple record types, and WPAD observations. |
| 05 | [HTTP Traffic Analysis](Lab-05-HTTP-Analysis/README.md) | Plaintext HTTP GET headers and a linked 200 OK response. |
| 06 | [TLS Traffic Analysis](Lab-06-TLS-Analysis/README.md) | Verified TLS 1.3 negotiation, cipher suite, SNI and hybrid key share. |
| 07 | [TCP Troubleshooting](Lab-07-TCP-Troubleshooting/README.md) | Duplicate ACKs, SACK, retransmissions and sequence gaps. |
| 08 | [Network Statistics & Traffic Profiling](Lab-08-Network-Statistics/README.md) | 32,350 captured frames, protocol distribution and traffic bursts. |

## Technical findings

### Layer 2 and Layer 3: ARP and ICMP

- **ARP:** Frames 6930 and 6931 show the router requesting the local host's MAC address and receiving a unicast reply. The request/reply capture interval is 56.2 µs.
- **ICMP:** Four Echo Requests to `1.1.1.1` have matching Echo Replies. The observed sample has 0% loss and a mean capture-derived round-trip time of 10.46 ms. Outbound TTL is 128 and reply TTL is 57; the exact hop count is not established.

[ARP request evidence](Lab-01-ARP-Analysis/screenshots/arp-request.png) · [ICMP reply evidence](Lab-02-ICMP-Analysis/screenshots/icmp-echo-reply.png)

### Transport layer: TCP connection lifecycle and troubleshooting

- Frames 464, 468 and 469 show a successful three-way handshake over IPv6 to TCP port 443. The observed handshake interval is 19.74 ms (SYN to final ACK).
- TCP MSS, window scaling, relative sequence and acknowledgment numbers, SACK capability, keep-alive traffic and orderly FIN-based termination are visible in the selected connection.
- A separate flow shows duplicate cumulative ACKs, SACK ranges and fast retransmissions, including frames 2863–2869. The pattern is consistent with recovery from missing or delayed data; the underlying cause was not established.

![TCP connection lifecycle](Lab-03-TCP-Handshake/screenshots/tcp-stream-7.png)

### Application layer: DNS and HTTP

- DNS queries and responses are correlated by transaction ID and record type. A, AAAA, HTTPS, CNAME and SOA records are visible. WPAD queries returning `127.0.0.1` are documented as a configuration-related observation requiring context, not a confirmed attack.
- An HTTP/1.1 GET request from a Steam-related client receives a `200 OK` response. Host, URI and User-Agent are visible in plaintext; the observed request-to-response interval is 13.58 ms. Gzip compression does not provide encryption.

[DNS packet evidence](Lab-04-DNS-Analysis/screenshots/dns-query-and-responses.png) · [HTTP packet evidence](Lab-05-HTTP-Analysis/screenshots/http-request-response.png)

### Encrypted traffic: TLS

The Client Hello (frame 470) and Server Hello (frame 488) belong to the same observed connection. The server selects **TLS 1.3**, **TLS_AES_128_GCM_SHA256** and **X25519MLKEM768**. The Client Hello advertises 16 cipher-suite entries including GREASE and exposes the SNI `www.youtube.com`. The legacy version fields are not evidence of a downgrade. A JA3S fingerprint is visible in the Server Hello; fingerprinting and other TLS metadata can support investigation but do not independently establish maliciousness.

![TLS Server Hello and selected parameters](Lab-06-TLS-Analysis/screenshots/server-hello.png)

### Network traffic profile

| Metric | Observed value |
| --- | ---: |
| Total frames | 32,350 |
| Captured bytes | 25,900,245 (25.9 MB) |
| Average displayed frame bit rate | 566 kbit/s |
| IPv6 | 21,571 (66.7%) |
| IPv4, including VLAN branch | 10,518 (32.5%) |
| UDP | 22,993 (71.1%) |
| TCP, including VLAN branch | 8,974 (27.7%) |
| QUIC | 19,984 (61.8%) |
| TLS over TCP | 3,131 (9.7%) |
| DNS | 883 (2.7%) |
| ARP | 261 (0.8%) |
| TCP / UDP conversations | 288 / 439 |
| Highest visible traffic spike | Approx. 4,400 packets/s near 96 s |

Protocol categories overlap across layers (e.g., QUIC over UDP); their percentages are not additive. The I/O graph uses one-second intervals, and its peak is estimated visually. Traffic spikes and TCP analysis flags are triage signals rather than proof of a security incident.

![Network traffic over time](Lab-08-Network-Statistics/screenshots/io-graphs.png)

## Wireshark display filter reference

These filters summarize the analysis workflow and include suggested follow-up filters. Frame and stream numbers refer to the original capture and will change in new captures.

| Filter | Purpose |
| --- | --- |
| `arp` | Inspect local address resolution. |
| `arp.opcode == 1` / `arp.opcode == 2` | Separate ARP requests and replies. |
| `icmp && ip.addr == 1.1.1.1` | Correlate ping requests and replies. |
| `tcp.flags.syn == 1` | Locate SYN and SYN-ACK segments. |
| `tcp.stream == 7` | Isolate the analyzed TCP conversation. |
| `dns` | Inspect DNS messages. |
| `dns.flags.response == 0` / `dns.flags.response == 1` | Separate DNS queries and responses. |
| `http` | Inspect plaintext HTTP traffic. |
| `http.request.method == "GET"` | Locate HTTP GET requests. |
| `tls.handshake.type == 1 \|\| tls.handshake.type == 2` | Inspect TLS Client Hello and Server Hello. |
| `tcp.analysis.flags` | Identify Wireshark TCP analysis events. |
| `tcp.analysis.retransmission` | Narrow to retransmission events. |
| `tcp.analysis.duplicate_ack` | Narrow to duplicate ACK events. |
| `quic` | Inspect QUIC traffic. |

## Skills practiced and security relevance

| Skill | Application |
| --- | --- |
| Packet capture and protocol inspection | Network visibility, troubleshooting and initial security triage. |
| TCP/IP analysis | Connection establishment, flow control, delivery behavior and recovery. |
| DNS and HTTP analysis | Query correlation and application metadata as investigation pivots. |
| TLS metadata analysis | Understand encryption boundaries, negotiated cryptographic parameters and observable metadata. |
| Traffic profiling | Establish a sample baseline, inspect conversations and identify bursts for further investigation. |
| Evidence-based reporting | Record frame references, measured intervals, findings and uncertainty without overstating conclusions. |

## Repository structure

```text
Wireshark-Network-Security-Analysis/
├── README.md
├── Lab-01-ARP-Analysis/
├── Lab-02-ICMP-Analysis/
├── Lab-03-TCP-Handshake/
├── Lab-04-DNS-Analysis/
├── Lab-05-HTTP-Analysis/
├── Lab-06-TLS-Analysis/
├── Lab-07-TCP-Troubleshooting/
└── Lab-08-Network-Statistics/
```

Each lab directory contains an English `README.md` and a `screenshots/` folder with supporting evidence. Start with the lab index to access the complete reports.

## Evidence, privacy and scope

- The reports are based on 16 screenshots of real captured traffic. Device identifiers have been redacted where relevant; private IPv4 addresses, remote endpoints and selected DNS names are retained for technical context.
- Raw PCAP files were not provided for this repository. The findings cannot be independently replayed from the published files; some packet fields and statistics are not visible in the screenshots.
- Capture-derived time differences are sample measurements, not guarantees of overall network performance.
- No malware execution, confirmed attack detection, port-scanning exercise, ARP poisoning test, DNS tunneling investigation, TLS decryption or production incident response is claimed as completed work.

## Conclusion

The eight labs demonstrate a practical foundation in network traffic inspection, protocol analysis, TCP troubleshooting and security-oriented traffic triage. They establish a starting point for future hands-on work with SIEM, endpoint telemetry, IDS/IPS and SOC investigations.
