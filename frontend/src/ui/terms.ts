/** Beginner-friendly glossary — shown in hover tooltips. */
export const TERMS: Record<string, string> = {
  // ── Protocols ──────────────────────────────────────────────────
  TCP:    "Transmission Control Protocol. Establishes a connection via a 3-way handshake and guarantees data is delivered in order and without loss.",
  UDP:    "Connectionless protocol. Transmits quickly without a connection but does not guarantee ordering or delivery. Used for DNS, video, and games.",
  ICMP:   "Internet Control Message Protocol. The foundation of network diagnostic tools such as ping and traceroute.",
  ICMP6:  "ICMP for IPv6. Used for ping and route tracing in IPv6 environments.",
  DNS:    "Domain Name System. The internet's phone book that translates 'google.com' into a numeric IP address.",
  TLS:    "Transport Layer Security. The core of HTTPS encryption. Encrypts data to prevent eavesdropping and tampering.",
  HTTP:   "Web browser-to-server communication protocol. Unencrypted, so its contents can be exposed when packets are intercepted.",
  HTTPS:  "HTTP + TLS encryption. The current standard for secure web communication.",
  ARP:    "Address Resolution Protocol. Translates an IP address into a MAC (physical) address. Sometimes abused in ARP spoofing attacks.",
  GRE:    "Generic Routing Encapsulation. A tunneling protocol that encapsulates packets inside another protocol.",
  ESP:    "IPsec ESP. Used to encrypt and authenticate packets in a VPN.",
  SCTP:   "Stream Control Transmission Protocol. Combines the strengths of TCP and UDP, mainly used in telecom infrastructure.",

  // ── TCP Flags ────────────────────────────────────────────────
  SYN:        "Connection start signal. The first step of the TCP 3-way handshake.",
  ACK:        "Acknowledgment signal. Means 'the previous packet was received successfully'.",
  "SYN+ACK":  "The handshake response a server sends to accept a connection request.",
  FIN:        "Connection termination request. The signal that 'there is no more data to send'.",
  RST:        "Forced connection reset. Indicates an abnormal termination or a refused connection. Many RSTs suggest firewall blocking or a port scan.",
  PSH:        "Delivers data immediately to the upper layer without buffering. Used for real-time communication.",
  "FIN+ACK":  "A normal termination pattern that sends a connection close request and an acknowledgment at the same time.",
  "RST+ACK":  "Forcibly resets a connection while also acknowledging receipt.",
  "PSH+ACK":  "Immediate data delivery + acknowledgment. The most common pattern in ordinary data transfer.",
  URG:        "Contains urgent data. Flags data that needs to be processed immediately.",

  // ── MITRE ATT&CK ─────────────────────────────────────────────
  T1046: "Network Service Scanning — reconnaissance that probes open ports and services to find exploitable entry points.",
  T1071: "Application Layer Protocol — a pattern that disguises itself as a legitimate protocol to communicate periodically with a C2 (command and control) server.",
  T1110: "Brute Force — an attack that repeatedly tries large numbers of passwords or credentials to hijack an account.",
  T1041: "Exfiltration Over C2 Channel — a technique where malware leaks internal data outward through a C2 channel.",
  T1498: "Network Denial of Service — overwhelms a service by flooding it with massive traffic from many distributed sources.",
  T1499: "Endpoint Denial of Service — disrupts communication with a specific host using methods such as RST flooding.",

  // ── Attack Types ─────────────────────────────────────────────
  PortScan:    "Port scan. Reconnaissance where an attacker probes a target system for open services.",
  Beacon:      "Beacon. A pattern where an infected system periodically signals the attacker's C2 server.",
  BruteForce:  "Brute-force attack. Repeatedly tries passwords against SSH, FTP, etc. to bypass authentication.",
  Exfiltration: "Data exfiltration. Smuggling sensitive internal data out to an external destination.",
  DDoS:        "Distributed Denial of Service. Many zombie PCs send traffic simultaneously to overwhelm a server.",
  CommFailure: "Communication failure. An abnormally high RST ratio — possibly a service disruption or firewall blocking.",

  // ── Severity ────────────────────────────────────────────────
  HIGH:   "Immediate action required. An active attack or a serious threat indicator has been detected.",
  MEDIUM: "Increase monitoring. A potential threat is present — further verification is recommended.",
  LOW:    "Caution needed. Anomalies are present but the current threat level is low.",
  CLEAN:  "No threat. No attack patterns were found in the analyzed traffic.",
}
