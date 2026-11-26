# Lab 03 — TCP Three-Way Handshake & Connection Lifecycle

## Objective
Analyze a real TCP connection over IPv6 in Wireshark, identify the three-way handshake, interpret relative sequence and acknowledgment numbers, and follow the connection through TLS traffic, keep-alive and orderly termination.

## Environment
- Wireshark on a Windows workstation
- Client: local workstation (public IPv6 address redacted)
- Remote IPv6 endpoint: `2001:4860:4828:400::`
- Client port: `51163`; server port: `443`
- TLS Client Hello SNI: `www.youtube.com`
- TCP stream index: `7`
- Evidence: one screenshot of the conversation; no raw PCAP supplied.

## Methodology
Identify TCP SYN packets and isolate a single conversation using its TCP stream index. The following display filters reproduce the analysis on the same capture (the stream index may differ in a new capture):

```wireshark
tcp.flags.syn == 1
tcp.stream == 7
```

Inspect the SYN, SYN-ACK and ACK frames, then follow subsequent TLS records and TCP termination flags. Calculate timing from relative capture timestamps.

## Packet analysis — TCP three-way handshake

| Frame | Direction | Flags | Relative Seq | Relative Ack | Capture time (s) | Frame length |
|---|---|---|---:|---:|---:|---:|
| 464 | Client → Server | SYN | 0 | Not valid (ACK flag unset) | 7.276000200 | 86 B |
| 468 | Server → Client | SYN, ACK | 0 | 1 | 7.295680000 | 86 B |
| 469 | Client → Server | ACK | 1 | 1 | 7.295740900 | 74 B |

The client initiates the connection with SYN. The server acknowledges the client's SYN and sends its own SYN. The final client ACK acknowledges the server's SYN. Wireshark uses relative sequence numbers in this view; each SYN consumes one sequence number even with no TCP payload.

### TCP options and flow control

- Client SYN: MSS 1440 bytes, displayed window scale multiplier 256, SACK permitted.
- Server SYN-ACK: MSS 1432 bytes, displayed window scale multiplier 256, SACK permitted.
- Selected SYN: 32-byte TCP header, zero TCP payload, advertised window 65535 bytes, flags `0x002`.
- The checksum is marked unverified; this does not establish a checksum error.

## Timing analysis

- SYN to SYN-ACK: approximately 19.680 ms (capture-derived handshake RTT estimate).
- SYN to final ACK: approximately 19.741 ms.
- SYN to final termination ACK: approximately 88.276 s (observed connection lifetime).

These values are differences between capture timestamps, not guarantees of application response time or network-wide latency.

## TLS and connection lifecycle

| Frame | Observed event |
|---|---|
| 470 | TLS Client Hello with SNI `www.youtube.com` |
| 488 | TLS Server Hello |
| 489 | TLS Change Cipher Spec |
| 493, 495, 497 | TLS application-data records visible in the conversation |
| 3968, 3969 | TCP Keep-Alive and Keep-Alive ACK |
| 8875 | Client FIN, ACK |
| 8897 | Server FIN, ACK |
| 8898 | Client final ACK |

Wireshark labels the TLS traffic as TLSv1.3. The observed TLS records and subsequent TCP acknowledgments are consistent with an established encrypted session. Application contents were not decrypted or examined. The FIN exchange shows an orderly bidirectional shutdown in the displayed stream, with the server combining its acknowledgment and FIN in one segment.

## Screenshot

![TCP stream 7 — handshake, TLS traffic and connection termination](screenshots/tcp-stream-7.png)

Privacy note: the workstation's IPv6 address, device MAC addresses and capture-interface identifier were masked in the published evidence. Other visible fields are retained.

## Security and troubleshooting relevance
A completed three-way handshake establishes TCP-level connectivity between the observed endpoints. Repeated SYN packets without a SYN-ACK may indicate filtering, packet loss, an unavailable service or other issues; the handshake alone cannot determine the cause. TCP connection patterns can support investigations of scanning and availability issues, but no attack is established by this sample. A successful TCP/TLS exchange alone does not establish that an endpoint is trustworthy or that application-layer requests succeeded.

## Skills practiced
- Wireshark TCP stream isolation and packet inspection
- TCP flags and relative sequence/acknowledgment analysis
- IPv6 and transport-layer endpoint identification
- MSS, window scaling and SACK interpretation
- Capture-based handshake timing
- TLS metadata, keep-alive and FIN-based connection termination analysis
- Evidence-based network and security reporting

## Limitations and conclusion
This screenshot demonstrates a completed TCP handshake, subsequent TLS traffic and an orderly connection closure. Only the SYN detail tree is expanded; other packet fields are taken from the visible packet list. Without the original PCAP, checksum validation, deeper TLS inspection, exact application contents and comprehensive retransmission analysis were not performed. Findings apply to the displayed conversation only.
