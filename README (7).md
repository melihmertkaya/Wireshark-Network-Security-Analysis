# Lab 08 — Network Statistics & Traffic Profiling

## Objective
Use Wireshark statistics to establish an observed traffic profile, identify dominant protocols and conversation types, and recognize traffic spikes for network troubleshooting and SOC triage.

## Environment and methodology
- Tool: Wireshark; Wi-Fi capture from a personal network.
- Statistics views: Protocol Hierarchy, Ethernet Conversations, TCP Conversations, and I/O Graphs.
- I/O graph interval: 1 second; all packets and `tcp.analysis.flags` series.
- Evidence: four screenshots. Ethernet endpoint MAC address columns are redacted; private IPv4 and remote server IPv4 addresses in the TCP view are retained for technical context.
- The original PCAP and exported statistics are not available. Values are transcribed from the screenshots, with graph peaks estimated visually.

## 1. Protocol hierarchy

![Protocol hierarchy](screenshots/protocol-hierarchy.png)

| Metric | Observed value |
| --- | ---: |
| Total frames | 32,350 |
| Total captured frame bytes | 25,900,245 (25.9 MB) |
| Average displayed frame bit rate | 566 kbit/s |
| IPv6 frames | 21,571 (66.7%) |
| IPv4 frames, including VLAN branch | 10,518 (32.5%) |
| UDP | 22,993 (71.1%) |
| TCP, including VLAN branch | 8,974 (27.7%) |
| QUIC | 19,984 (61.8%) |
| TLS over TCP | 3,131 (9.7%) |
| DNS | 883 (2.7%) |
| ARP | 261 (0.8%) |

Percentages use the total frame count as the denominator. Counts for the same protocol are summed across the visible hierarchy branches. Layered protocol categories overlap (e.g., QUIC over UDP and TLS over TCP), so these percentages should not be added together. QUIC is the dominant visible higher-layer protocol; QUIC alone does not prove that every such packet carries HTTP/3.

## 2. Ethernet conversations

![Ethernet conversations](screenshots/ethernet-conversations.png)

| Conversation category | Count |
| --- | ---: |
| Ethernet | 21 |
| IPv4 | 51 |
| IPv6 | 106 |
| TCP | 288 |
| UDP | 439 |

The largest visible Ethernet conversation has 31,724 packets and approximately 26 MB (rounded by Wireshark). Its original endpoints correspond to the local computer and the router observed in the earlier protocol labs. This is consistent with most captured traffic traversing the local gateway. Conversation counts are layer-specific and are not counts of unique hosts or verified successful application sessions.

## 3. TCP conversations

![TCP conversations](screenshots/tcp-conversations.png)

The TCP tab displays 288 conversations. In the visible rows, the local IPv4 endpoint `192.168.1.148` communicates with multiple remote endpoints, predominantly involving TCP port 443. A visible row also includes remote port 27018. Port numbers alone do not establish the application, ownership, or maliciousness of a connection.

The screenshot is ordered by Address A, not by bytes; byte and packet-count columns are outside the visible area. The highest-volume TCP conversation therefore cannot be identified from this evidence.

## 4. Traffic over time

![I/O graphs](screenshots/io-graphs.png)

- The black line represents all captured packets per second.
- The red series represents TCP analysis flags, not a direct measurement of packet loss or attacks.
- The largest visible spike is approximately 4,400 packets/s near 96 seconds.
- Additional bursts are visible around 310–365 seconds.

Traffic spikes are useful triage signals but may reflect normal downloads, streaming, application updates, or other activity. The screenshot does not establish their source or cause.

## 5. Security and troubleshooting considerations
- Establish a baseline over comparable time periods before treating deviations as anomalous.
- Correlate spikes with endpoint activity, conversations, and packet-level timestamps.
- Inspect TCP analysis flags in context, considering retransmissions, reordering, and capture artifacts.
- Recognize that QUIC and TLS can limit plaintext application inspection. Metadata such as endpoint addresses, ports, timing, and traffic volume may still support investigations.

### Suggested follow-up display filters

```text
quic
tls
tcp.port == 443
tcp.analysis.flags
ip.addr == 192.168.1.148
```

These are suggested follow-up filters, not additional completed experiments.

## Limitations and conclusion
The four screenshots demonstrate protocol distribution, conversation counts, and temporal traffic profiling. Exact spike values, connection rankings by bytes, capture drop rates, and causes of the observed bursts cannot be established without the original capture or additional statistics. No confirmed security incident is claimed.

## Skills practiced
Protocol hierarchy analysis, traffic baselining, Ethernet and TCP conversation inspection, I/O graph interpretation, anomaly triage, and evidence-based network reporting.
