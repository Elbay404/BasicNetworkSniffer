# Basic Network Sniffer

Python packet sniffer built for Cyber Security Task 1. Captures live
network traffic and displays source/destination IP, protocol, ports,
and payload, with optional protocol decoding and suspicious-activity
detection.

Two implementations are included:

- **`main.py` + `utils.py`** — the main deliverable, built with
  [Scapy](https://scapy.net/). Practical, extensible, filters at the
  kernel level using BPF syntax (same as `tcpdump`/Wireshark).
- **`raw_sniffer.py`** — a from-scratch version using Python's raw
  `socket` module, manually unpacking Ethernet/IP/TCP/UDP/ICMP headers
  with `struct`. Kept to show understanding of protocol internals
  (how headers are actually laid out byte by byte).

## Requirements

- Python 3
- Linux (raw sockets required — tested on Kali Linux)
- Root privileges to run

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> Note: the venv folder is named `.venv` (with a leading dot). If you
> create it with a different name, adjust the run commands below to match.

## Usage

Run with sudo, using the venv's Python directly so scapy is found:

```bash
sudo .venv/bin/python3 main.py
```

### Basic options

```bash
sudo .venv/bin/python3 main.py -i eth0                 # specific interface
sudo .venv/bin/python3 main.py -f "tcp port 443"        # only HTTPS traffic
sudo .venv/bin/python3 main.py -f "icmp"                # only pings
sudo .venv/bin/python3 main.py -c 50                    # stop after 50 packets
```

### Optional protocol decoders

Off by default — enable them explicitly to see more detail:

```bash
sudo .venv/bin/python3 main.py --show-tls               # decode TLS record header (type, version, length)
sudo .venv/bin/python3 main.py --show-dns                # decode DNS query domain names
```

### Optional suspicious-activity detection

```bash
sudo .venv/bin/python3 main.py --detect
```
Flags, as `[ALERT]` lines, when it sees:
- plaintext credentials in a payload (e.g. `password=`)
- traffic on port 443 that doesn't look like valid TLS
- unusually long or high-entropy DNS queries (possible DNS tunneling)
- a port-scan pattern (many SYNs to different ports from one host in a short window)

These are teaching-level heuristics, not a production IDS — expect
some false positives.

### Finding alerts in the output

With `--detect` on, normal packet output can be dense — an `[ALERT]`
line can easily scroll by unnoticed among everything else. A few ways
to make alerts easier to actually see:

**Filter to just alerts (and use `-u` so output isn't buffered when piped):**
```bash
sudo .venv/bin/python3 -u main.py --detect | grep "ALERT"
```

**Filter to alerts plus the SYN packets, when testing port-scan detection:**
```bash
sudo .venv/bin/python3 -u main.py --detect | grep -E "flags=S |ALERT"
```

**Or just run it plainly and scroll/search the terminal afterward** — no
pipe needed, avoids buffering entirely:
```bash
sudo .venv/bin/python3 main.py --detect
```

### Testing each alert type on purpose

Since most of these heuristics stay silent during normal, healthy
traffic, here's how to deliberately trigger each one to confirm it
works:

**Plaintext credentials** — visit any HTTP (not HTTPS) login form, or:
```bash
curl http://neverssl.com/?password=test123
```

**TLS/port-443 mismatch** — send non-TLS data on port 443 with netcat:
```bash
# terminal 1
sudo nc -lvp 443
# terminal 2
echo "THIS IS NOT TLS AT ALL" | nc localhost 443
```

**Suspicious DNS** — query a long, random-looking subdomain:
```bash
nslookup xkqjzpvblqmrztxnwplfghsjdytmwqkzplr.example.com
```

**Port scan** — scan an external test host designed for this
(scanning your own machine's IP from itself is unreliable, see Known
limitations below):
```bash
sudo nmap -sS -p 1-100 scanme.nmap.org
```

### Save a capture to disk (pcap)

```bash
sudo .venv/bin/python3 main.py --pcap capture.pcap
```
Saves every captured packet to a standard **pcap** file — the same
format used by Wireshark and tcpdump. Packets are written to disk as
they arrive (not buffered until the end), so the file stays valid
even if you stop the sniffer mid-capture with Ctrl+C.

Open the result in Wireshark for deeper inspection:
```bash
wireshark capture.pcap
```
Or transfer/view it however you like — pcap is a universal, portable
format for saved network traffic, useful for keeping evidence from a
capture session or re-analyzing traffic without needing to recapture it live.

### Combine flags freely

```bash
sudo .venv/bin/python3 main.py -i eth0 --show-tls --show-dns --detect
```

### Generating readable traffic to test with

```bash
ping google.com                          # ICMP
curl http://neverssl.com                 # plain HTTP (readable payload)
nslookup example.com                     # DNS query
```

The raw-socket version runs the same way, no arguments:

```bash
sudo .venv/bin/python3 raw_sniffer.py
```

## Understanding raw_sniffer.py output

Each captured packet prints as nested blocks: Ethernet Frame → IPv4
Packet → TCP/UDP/ICMP Segment → Payload. A guide to reading them:

**Ethernet Frame**
- `Destination MAC` / `Source MAC` — hardware addresses of the two
  ends of this hop (often your VM's virtual NIC and the VirtualBox/
  VMware virtual gateway, not the true end-to-end hosts)
- `Protocol` — the EtherType; `8` means the payload is IPv4

**IPv4 Packet**
- `Version` — should always be `4` here
- `Header Length` — usually `20` bytes unless IP options are present
- `TTL` — hop count remaining; Linux defaults to `64`, Windows to
  `128` — a rough OS fingerprint
- `Protocol` — the IP protocol number: `6` = TCP, `17` = UDP, `1` = ICMP
- `Source IP` / `Destination IP` — the actual hosts communicating

**TCP Segment**
- `Source Port` / `Destination Port` — `443` = HTTPS, `80` = HTTP,
  `22` = SSH, etc.
- `Sequence` / `Acknowledgment` — TCP's byte-tracking numbers, used
  to detect lost or reordered data
- `Flags` — the connection's state. A lone `SYN=1` starts a
  connection, `SYN=1 ACK=1` accepts it, a plain `ACK=1` with no other
  flags is just acknowledging receipt (and will have an **empty**
  payload — that's normal, not a bug), `PSH=1 ACK=1` carries actual
  data, and `FIN=1 ACK=1` closes the connection

**UDP Segment**
- Simpler than TCP — just ports and length, no handshake or flags,
  since UDP is connectionless

**ICMP Packet**
- `Type: 8` = Echo Request (an outgoing ping), `Type: 0` = Echo Reply
  (the response coming back)
- Standard Linux `ping` pads its payload with a recognizable
  incrementing byte sequence (`10 11 12 13...`) — this is normal and
  expected, not suspicious. An ICMP payload that *doesn't* follow
  this pattern (e.g. looks like readable text or repeats oddly) can
  be a sign of ICMP tunneling, since firewalls often inspect ICMP
  less closely than TCP/UDP

**Payload**
- Printed as readable text when the bytes are genuinely printable
  (HTTP, DNS queries), or as hex when they're not (encrypted TLS
  traffic, or binary protocol data) — this is decided automatically,
  not something you need to configure
- Encrypted (TLS/HTTPS) payloads are *expected* to show as unreadable
  hex — that confirms the encryption is working correctly, it isn't
  a sign anything is broken

## Features

- Displays source IP, destination IP, protocol (TCP/UDP/ICMP), ports, and payload
- BPF filter support (`-f`) for targeted capture
- Packet count limit (`-c`) for bounded captures
- Optional TLS record header decoding (`--show-tls`)
- Optional DNS query name decoding (`--show-dns`)
- Optional suspicious-activity alerts (`--detect`): plaintext credentials,
  TLS/port mismatch, suspicious DNS, port-scan detection
- Optional pcap file logging (`--pcap FILE`) for later inspection in Wireshark
- Raw-socket version demonstrates manual header parsing (Ethernet, IP, TCP, UDP, ICMP)

## Known limitations

- **`--detect`'s TLS/port-443 check (`TLSRecordTracker`) tracks
  in-progress TLS records per connection** to avoid flagging normal
  mid-record continuation segments as suspicious (a single TLS record
  is often larger than one packet's MTU, so the OS splits it across
  several TCP segments — only the *first* segment legitimately starts
  with a valid TLS type byte). This fixes the false positives seen in
  the common in-order case. It still assumes packets arrive in order
  with no retransmissions — genuinely out-of-order or retransmitted
  segments (rare in a normal live capture, but possible) can still
  produce a false positive, since a full fix needs complete TCP
  stream reassembly, which is beyond the scope of this basic sniffer.
- All `--detect` heuristics are teaching-level pattern checks, not a
  production IDS (Suricata/Zeek use far more context and tuning) —
  expect some false positives generally, not just for the TLS check.
- Testing `--detect`'s port-scan detector against your own machine's
  IP from itself is unreliable: Linux often routes such traffic
  through the loopback interface instead of the real one, so the
  sniffer may never see the outgoing SYN packets. Test port-scan
  detection using traffic from a genuinely separate machine (or a
  scan against an external test host) instead.

## Project structure

```
Basic-Network-Sniffer/
│
├── main.py            # entry point (Scapy version)
├── utils.py            # protocol detection, decoders, and detection heuristics
├── raw_sniffer.py       # from-scratch raw socket version
├── requirements.txt
└── README.md
```