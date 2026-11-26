# Lab 07 — TCP Troubleshooting

## Objective
Identify TCP analysis events in a real network capture and interpret their implications for network troubleshooting and SOC triage.

## Environment and methodology
- Tool: Wireshark; previously captured traffic from a personal network.
- Display filter: `tcp.analysis.flags` (the filter bar is not visible in the supplied screenshot).
- Evidence: packet-list screenshot with Wireshark-generated analysis labels. IPv6 endpoint identifiers have been replaced with directional labels for privacy.
- No original PCAP or expanded TCP headers were provided for this lab.

## Evidence

![TCP analysis events](screenshots/tcp-analysis-flags.png)

## Observed events

| Frame | Wireshark event | Interpretation |
| --- | --- | --- |
| 1855 | TCP Previous segment not captured | A sequence gap was detected in the observed traffic; capture loss or actual network loss may explain it. |
| 1857 | TCP Out-of-Order | Segment classified as arriving outside expected sequence order. |
| 2764–2768, 2788, 2806 | TCP Retransmission (SYN, ACK) | Repeated handshake responses; final handshake outcome and reason not established. |
| 2863–2867 | TCP Dup ACK | Repeated cumulative acknowledgment of 19120 with SACK information. |
| 2868–2869 | TCP Fast Retransmission | Client-to-server data segments marked as fast retransmissions. |
| 2888–2890 | TCP Fast Retransmission | Additional recovery-related segments in the same visible endpoint/port pair. |
| 2897 | TCP Dup ACK | Duplicate ACK counter reaches #30 in the displayed sequence; this is not a packet-loss count. |

## Focused flow analysis
The visible IPv6 flow uses client TCP port 13527 and server TCP port 443. Frames 2863–2867 show ACK=19120, while SACK blocks report receipt of later byte ranges. Frame 2868 shows Seq=19120 and Len=1360 in the opposite direction; frame 2869 shows Seq=20480 and Len=1360. Wireshark labels both as fast retransmissions. The observed pattern is consistent with TCP attempting to recover missing or delayed data.

SACK communicates received byte ranges beyond the cumulative ACK. Duplicate ACKs can help trigger fast retransmission instead of waiting solely for a retransmission timeout. These are TCP recovery mechanisms, not proof of a cyberattack.

## Useful follow-up display filters

```text
tcp.analysis.retransmission
tcp.analysis.fast_retransmission
tcp.analysis.duplicate_ack
tcp.analysis.out_of_order
tcp.analysis.lost_segment
tcp.port == 13527 && tcp.port == 443
```

These are suggested follow-up filters; separate captures with these filters were not performed for this report.

## Troubleshooting and security considerations
- Isolate the relevant flow using its TCP stream index and inspect the original segment, ACK progression and SACK ranges.
- Compare capture points and interface error/drop counters to distinguish capture artifacts from real delivery problems.
- Consider congestion, packet loss and reordering as hypotheses, not confirmed root causes.
- Do not classify retransmissions or duplicate ACKs alone as malicious activity. Correlate with firewall, endpoint and other network telemetry when investigating security incidents.

## Limitations and conclusion
The screenshot demonstrates TCP analysis flags and a plausible recovery pattern. It does not establish the root cause, actual loss rate, total retransmission count, RTT, or the final recovery outcome. No claim of a confirmed attack or successful remediation is made.

## Skills practiced
TCP sequence and acknowledgment interpretation, SACK recognition, retransmission analysis, packet-level troubleshooting, evidence-based reporting and security triage.
