# Lab 05 — HTTP Traffic Analysis

## Objective
Analyze a real HTTP request and response in Wireshark, inspect application-layer headers, correlate network and transport information, and explain the security implications of unencrypted HTTP.

## Environment
- Windows workstation and Wireshark
- Client IPv4: `192.168.1.148`
- Remote IPv4: `195.175.182.11`
- Evidence: one screenshot of the HTTP packet list and expanded GET request; no PCAP supplied.

## Methodology
Inspect the HTTP conversation, identify the requesting client and remote endpoint, correlate the request with the linked response frame, and interpret the visible headers and capture timestamps. Relevant Wireshark display filters for reproducing or narrowing the analysis on the original capture:

```wireshark
http
http.request.method == "GET"
http.response.code == 200
http && ip.addr == 195.175.182.11
```

## Selected request — frame 21391

| Field | Observed value |
|---|---|
| HTTP version / method | HTTP/1.1 / GET |
| Source / destination IPv4 | 192.168.1.148 / 195.175.182.11 |
| TCP source / destination port | 32692 / 80 |
| Captured frame length | 332 bytes |
| TCP payload length | 278 bytes |
| Host | clientconfig.akamai.steamstatic.com |
| Request path | `/appinfo/4656000/sha/f0f9f39d818dbad47e40fb4df984873144660d22.txt.gz` |
| User-Agent | Valve/Steam HTTP Client 1.0 |
| Accept-Encoding | gzip, identity, *;q=0 |
| Linked response frame | 21395 |

The host name, request path and User-Agent are visible in plaintext. The path suggests a compressed application-information resource, but the file content was not examined.

## Request and response correlation

| Frame | Relative capture time (s) | Direction | Summary | Captured length |
|---:|---:|---|---|---:|
| 21391 | 239.717596100 | Client → server | GET HTTP/1.1 | 332 bytes |
| 21395 | 239.731180600 | Server → client | HTTP/1.1 200 OK (application/gzip) | 1051 bytes |

Observed request-to-response interval: **13.5845 ms**, calculated by subtracting the capture timestamps. This is not necessarily the TCP RTT or the complete file-download time.

The 200 OK status indicates successful HTTP processing of the request. The response summary identifies an `application/gzip` media type; it does not independently verify the file contents or integrity. The request details link directly to response frame 21395.

## Security implications
- Plaintext HTTP exposes request metadata and potentially content to observers with access to the relevant network traffic.
- Host, URI and User-Agent are useful investigation pivots, but they alone do not establish an application's identity or the trustworthiness of a destination.
- Gzip compression is not encryption. HTTPS with properly validated TLS provides confidentiality and integrity in transit and server authentication.
- The observed host and User-Agent are consistent with Steam-related traffic. No malicious activity is established by this evidence; further investigation would be needed to assess file integrity or reputation.

## Screenshot
![HTTP GET request, headers and linked 200 OK response](screenshots/http-request-response.png)

Privacy note: MAC addresses, local device identifiers and capture-interface identifier were masked. Empty space in the packet list was removed for readability; packet rows and relevant protocol details remain visible.

## Skills practiced
- HTTP display filtering and request/response correlation
- TCP port and IPv4 endpoint inspection
- HTTP method, status code, Host and User-Agent interpretation
- Capture-based response timing
- Plaintext protocol security assessment and evidence-based reporting

## Limitations and conclusion
This screenshot demonstrates a successful HTTP GET exchange and readable request metadata. The response detail tree, complete response body, file integrity, server ownership and application process were not independently examined. Without the PCAP, these results cannot be independently replayed. The lab establishes a baseline for comparing plaintext HTTP with encrypted TLS traffic in the next lab.
