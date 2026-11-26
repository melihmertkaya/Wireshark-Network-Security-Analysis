# Lab 01 — ARP & MAC Address Analysis

## Objective
Analyze real ARP traffic using Wireshark, identify IPv4-to-MAC address resolution, distinguish broadcast requests from unicast replies, and establish a baseline for network security investigations.

## Lab Environment
- Platform: Windows, Wireshark
- Capture interface: Wi-Fi
- Router (observed ARP sender): `192.168.1.1` (Zyxel)
- Local host: `192.168.1.148` (Intel network adapter)
- Protocol: Address Resolution Protocol (ARP)

## Methodology
1. Capture local Wi-Fi traffic in Wireshark.
2. Apply the `arp` display filter.
3. Identify a matching ARP request and reply (frames 6930 and 6931).
4. Inspect ARP header fields, sender and target addresses, opcodes, and capture timestamps.
5. Compare normal address resolution with security-relevant observations.

## Wireshark Display Filters

| Filter | Purpose |
|---|---|
| `arp` | Display ARP traffic (used in this lab). |
| `arp.opcode == 1` | Isolate ARP requests. |
| `arp.opcode == 2` | Isolate ARP replies. |
| `arp.opcode == 1 && arp.dst.proto_ipv4 == 192.168.1.148` | Isolate requests for the local host. |
| `arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.1.148` | Isolate replies from the local host. |

The additional filters are provided for reproducing the analysis; only the general ARP filter is confirmed in the supplied capture overview.

## Packet Analysis

| Field | ARP Request | ARP Reply |
|---|---|---|
| Frame number | 6930 | 6931 |
| Relative capture time (s) | 433.106605900 | 433.106662100 |
| Hardware type | Ethernet (1) | Ethernet (1) |
| Protocol type | IPv4 (0x0800) | IPv4 (0x0800) |
| Hardware address length | 6 bytes | 6 bytes |
| Protocol address length | 4 bytes | 4 bytes |
| Opcode | Request (1) | Reply (2) |
| Sender IP | 192.168.1.1 | 192.168.1.148 |
| Target IP | 192.168.1.148 | 192.168.1.1 |
| Ethernet delivery | Broadcast | Unicast |
| Captured frame length | 42 bytes | 42 bytes |

### 1. ARP Request — Frame 6930
The router broadcasts a request asking which device owns `192.168.1.148`. The Ethernet destination and the captured ARP target hardware address are both broadcast (`ff:ff:ff:ff:ff:ff`) in this particular request.

![ARP request — frame 6930](screenshots/arp-request.png)

### 2. ARP Reply — Frame 6931
The local host responds directly to the router and advertises its MAC address. The sender and target IPv4 addresses are reversed relative to the request. The observed time difference between the two captured frames is 56.2 microseconds (0.0562 ms); this is a capture timestamp difference, not an end-to-end network latency measurement.

![ARP reply — frame 6931](screenshots/arp-reply.png)

## Key Findings
- A matching broadcast request and unicast reply demonstrate successful local IPv4-to-MAC resolution.
- Repeated request/reply exchanges for `192.168.1.148` appear in the visible traffic.
- Requests for `192.168.1.147` are also visible, with no corresponding replies in the provided excerpt. This does not establish whether that host was offline or whether replies existed elsewhere in the capture.
- The 42-byte captured length is consistent with a 14-byte Ethernet header and 28-byte Ethernet/IPv4 ARP message, excluding any unshown padding or FCS.

## Security Implications
ARP does not authenticate IP-to-MAC mappings. Forged ARP messages may enable ARP poisoning and traffic interception. Analysts can investigate inconsistent IP-to-MAC mappings, unexpected ARP replies, and changes to the gateway MAC address. These are indicators for further investigation, not conclusive proof of an attack.

No ARP spoofing or confirmed malicious activity was demonstrated in this lab. The selected request/reply pair is consistent with normal address resolution.

## Skills Practiced
- Wireshark packet capture and display filtering
- ARP header and opcode interpretation
- Layer 2 and Layer 3 address correlation
- Broadcast and unicast traffic differentiation
- Capture timestamp comparison
- Baseline network behavior analysis and security documentation

## Conclusion
This lab demonstrates practical analysis of a successful ARP exchange on a local network. The findings provide a foundation for network troubleshooting and future ARP spoofing detection exercises.

## Evidence & Privacy
The included screenshots are redacted copies of the actual captured frames. Device MAC addresses, MAC-derived aliases, and raw packet bytes are masked; private IPv4 addresses and packet evidence needed for the analysis are retained. The original PCAP was not supplied, so the findings are limited to the screenshots.
