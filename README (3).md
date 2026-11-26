# Lab 04 — DNS Traffic Analysis

## Objective
Inspect real DNS traffic in Wireshark, correlate queries with responses, identify DNS record types, and assess the security relevance of local name resolution.

## Environment
- Windows workstation and Wireshark
- IPv4 client: `192.168.1.148`; observed IPv4 DNS resolver: `192.168.1.1`
- IPv6 link-local DNS traffic also observed; local IPv6 and MAC addresses redacted
- Evidence: one screenshot, with the UDP and DNS query detail trees expanded. No PCAP supplied.

## Methodology
Inspect DNS query and response messages and correlate transaction IDs, queried names, record types and capture timestamps. The following Wireshark display filters can reproduce or narrow the analysis on the same capture:

```wireshark
dns
dns.flags.response == 0
dns.flags.response == 1
dns.id == 0x755c
dns.qry.name == "wpad.hgw.local"
```

## Selected packet — frame 2
| Field | Observed value |
|---|---|
| Query name | ssl.gstatic.com |
| Query type | HTTPS (type 65) |
| Transport | UDP over IPv6 |
| Source port | 63410 |
| Destination port | 53 |
| Transaction ID | 0x755c |
| DNS flags | 0x0100 (standard query, recursion desired) |
| Questions | 1 |
| Answer / Authority / Additional records | 0 / 0 / 0 |
| UDP length / payload | 41 / 33 bytes |
| Captured frame length | 95 bytes |

The UDP checksum is shown as unverified; this does not establish a checksum error.

## Query and response correlation
| Query frame | Response frame | Transaction ID | Name | Type | Observed response time |
|---:|---:|---|---|---|---:|
| 2 | 5 | 0x755c | ssl.gstatic.com | HTTPS | 4.772 ms |
| 3 | 6 | 0xf8c1 | ssl.gstatic.com | AAAA | 7.037 ms |
| 4 | 7 | 0x4aee | ssl.gstatic.com | A | 8.250 ms |
| 66 | 69 | 0x5313 | www.googleapis.com | A | 19.236 ms |

Response times are calculated from the relative capture timestamps. These are observed query-to-response intervals, not application latency. The HTTPS response summary shows an SOA record; a successful HTTPS answer cannot be established from that summary alone.

## Record types observed
- **A:** maps a name to an IPv4 address.
- **AAAA:** maps a name to an IPv6 address.
- **HTTPS:** provides service-binding parameters for HTTPS connections.
- **CNAME:** aliases one DNS name to another (e.g., `lh3.google.com` to `lh2.l.google.com` in the displayed responses).
- **SOA:** provides DNS zone authority information; it may appear in negative answers.

## Security observation — WPAD
Frames 74 and 76 show an A query and response for `wpad.hgw.local`, transaction ID `0x0468`, returning `127.0.0.1`. Frames 80 and 87 show another A query and response with the same returned address. Additional AAAA and HTTPS queries are visible. WPAD is associated with automatic proxy discovery. A loopback answer may reflect local resolver policy or another configuration; the screenshot alone cannot determine its origin or whether a proxy was actually used. No attack is established.

DNS investigation can help detect suspicious domain lookups, unexpected resolver changes and potential command-and-control traffic. Such findings require contextual evidence, baseline comparison and further analysis.

## Screenshot
![DNS queries, responses and UDP/DNS packet details](screenshots/dns-query-and-responses.png)

Privacy note: local IPv6 addresses, MAC addresses and the capture-interface identifier were masked. Private IPv4 addresses and the queried names remain visible for analysis.

## Skills practiced
- DNS display filtering and query/response correlation
- UDP port and header inspection
- DNS transaction ID and record-type interpretation
- Capture-based DNS response timing
- WPAD-related traffic identification and evidence-based security reporting

## Limitations and conclusion
The screenshot demonstrates DNS query/response exchanges over IPv4 and IPv6. Only the selected query detail tree is expanded; response findings come from the visible packet list. Without a PCAP or expanded response details, full response codes, record TTLs, DNSSEC validation and complete answer sections were not independently inspected. No malicious activity or DNS tunneling was established by this sample.
