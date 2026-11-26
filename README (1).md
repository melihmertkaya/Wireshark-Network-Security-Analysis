# Lab 02 — ICMP & Network Troubleshooting

## Objective
Analyze ICMP Echo Request and Echo Reply traffic, verify IPv4 reachability, correlate request/reply pairs, and estimate round-trip time using Wireshark capture timestamps.

## Environment
- Wireshark on a local Windows workstation
- Local IPv4 address: `192.168.1.148`
- Remote test destination: `1.1.1.1`
- Evidence: two screenshots of the same filtered capture; no raw PCAP available for this report

## Methodology
Inspect captured ICMP traffic with the following Wireshark display filter:

```wireshark
icmp && ip.addr == 1.1.1.1
```

Identify outgoing Echo Requests and incoming Echo Replies by direction, identifier, sequence number, and Wireshark's request/reply frame references. Compare the capture timestamps for each pair.

## Packet analysis

| Field | Echo Request | Echo Reply |
|---|---|---|
| Frame number | 20104 | 20105 |
| Source IPv4 | 192.168.1.148 | 1.1.1.1 |
| Destination IPv4 | 1.1.1.1 | 192.168.1.148 |
| Relative capture time (s) | 120.563367200 | 120.573334400 |
| ICMP identifier (as displayed) | 0x0001 | 0x0001 |
| Sequence number (first displayed value) | 9 | 9 |
| IPv4 TTL | 128 | 57 |
| Captured frame length | 74 bytes | 78 bytes |
| 802.1Q header in summary | Not shown | Present; VID 0, PCP 0 |

The first request and reply have matching identifiers and sequence numbers, with reversed IP endpoints. The reply summary shows a four-byte 802.1Q header with VLAN ID 0 (priority tagging); this is consistent with the observed frame-length difference. The displayed lengths are frame lengths, not ICMP payload lengths.

## Round-trip time and reachability

| Sequence | Request frame | Reply frame | Estimated RTT (ms) |
|---|---:|---:|---:|
| 9 | 20104 | 20105 | 9.967 |
| 10 | 20114 | 20115 | 10.393 |
| 11 | 20118 | 20119 | 10.803 |
| 12 | 20125 | 20126 | 10.658 |

- Observed requests: 4; matching replies: 4.
- Observed packet loss within this sample: 0%.
- Mean capture-derived RTT: approximately 10.46 ms.
- The observed reply TTL is 57. The exact hop count cannot be established without knowing the remote sender's initial TTL.

## Screenshots

### Echo Request — frame 20104
![ICMP Echo Request](screenshots/icmp-echo-request.png)

### Echo Reply — frame 20105
![ICMP Echo Reply](screenshots/icmp-echo-reply.png)

Device MAC addresses and capture-interface identifiers have been redacted for public sharing.

## Security and troubleshooting relevance
ICMP is useful for basic connectivity checks and latency observations. A missing reply may result from filtering, rate limiting, packet loss, or an unreachable destination; it is not by itself evidence of an attack. Successful ICMP replies do not prove that DNS, TCP, HTTPS, or other application services are working. The four observed exchanges provide a small example of normal ICMP traffic, not a comprehensive security assessment.

## Skills practiced
- Wireshark display filtering
- ICMP request/reply correlation
- IPv4 addressing and TTL interpretation
- Capture-based RTT estimation
- Evidence-based network troubleshooting and reporting

## Limitations and conclusion
The screenshots show successful ICMP exchanges with the remote endpoint. The IPv4 and ICMP detail trees are collapsed; numeric ICMP Type/Code fields, checksums, and payload contents were not independently inspected. The report is limited to visible evidence and does not establish long-term loss, exact hop count, or overall network health.
