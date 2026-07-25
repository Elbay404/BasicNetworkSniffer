"""
utils.py
--------
Helper functions for the Basic Network Sniffer (Scapy version):
protocol identification and payload formatting.
"""

from scapy.all import IP, TCP, UDP, ICMP, Raw
from collections import OrderedDict
import time

try:
    from scapy.layers.dns import DNS, DNSQR
except ImportError:
    DNS, DNSQR = None, None


def describe_protocol(pkt):
    """Return a human-readable protocol name for the packet."""
    if pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(UDP):
        return "UDP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def format_payload(pkt, max_bytes=80):
    """Return a printable preview of the packet's raw payload, or None
    if there is no payload layer."""
    if not pkt.haslayer(Raw):
        return None

    payload = pkt[Raw].load[:max_bytes]
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload.hex()


# ---------------------------------------------------------------------------
# Optional protocol decoders (enabled via --show-tls / --show-dns in main.py)
# ---------------------------------------------------------------------------

TLS_CONTENT_TYPES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "ApplicationData",
}

TLS_VERSIONS = {
    (3, 1): "TLS 1.0",
    (3, 2): "TLS 1.1",
    (3, 3): "TLS 1.2 / 1.3*",  # TLS 1.3 records still report 0x0303
}

VALID_TLS_CONTENT_BYTES = {20, 21, 22, 23}


def parse_tls_record(pkt):
    """Decode just the 5-byte TLS record header (content type, version,
    length) from a packet's raw payload. Does NOT decrypt anything --
    only the header is ever sent in plaintext. Returns None if the
    payload doesn't look like a TLS record.
    """
    if not pkt.haslayer(Raw):
        return None

    data = pkt[Raw].load
    if len(data) < 5:
        return None

    content_type = data[0]
    if content_type not in TLS_CONTENT_TYPES:
        return None  # not a recognizable TLS record

    version = (data[1], data[2])
    length = int.from_bytes(data[3:5], "big")

    return {
        "content_type": TLS_CONTENT_TYPES[content_type],
        "version": TLS_VERSIONS.get(version, f"unknown ({version[0]}.{version[1]})"),
        "record_length": length,
    }


def parse_dns_query(pkt):
    """Extract the queried domain name from a DNS query packet.
    DNS is unencrypted, so this is a real plaintext decode, not a guess.
    Returns None if the packet isn't a DNS query.
    """
    if DNS is None or not pkt.haslayer(DNS):
        return None

    dns_layer = pkt[DNS]
    if dns_layer.qr != 0 or not pkt.haslayer(DNSQR):  # qr=0 -> query, qr=1 -> response
        return None

    qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
    return qname


# ---------------------------------------------------------------------------
# Lightweight suspicious-activity detection (enabled via --detect in main.py)
# These are simple heuristics for learning purposes, not a production IDS --
# real tools (Snort/Suricata/Zeek) use far more context and tuning.
# ---------------------------------------------------------------------------

CREDENTIAL_KEYWORDS = [b"password=", b"passwd=", b"pwd=", b"login=", b"user=", b"username="]


def check_plaintext_credentials(pkt):
    """Flag payloads that look like they carry credentials in plaintext
    (e.g. an HTTP form submission). Only meaningful on unencrypted
    traffic -- TLS payloads are ciphertext and will never match."""
    if not pkt.haslayer(Raw):
        return None

    data = pkt[Raw].load.lower()
    for keyword in CREDENTIAL_KEYWORDS:
        if keyword in data:
            return f"possible plaintext credentials (matched '{keyword.decode()}')"
    return None


def check_tls_port_mismatch(pkt):
    """Flag traffic on port 443 whose payload does NOT start with a
    valid TLS record type byte. Real HTTPS traffic should always start
    with 0x14-0x17; anything else on port 443 is worth a second look
    (could be a non-TLS protocol tunneled over the HTTPS port).

    NOTE: this stateless version has a known false-positive rate on
    multi-packet TLS records (see TLSRecordTracker below for a
    connection-aware version that fixes this in the common case).
    Kept here for reference / simpler standalone use.
    """
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return None

    if pkt[TCP].sport != 443 and pkt[TCP].dport != 443:
        return None

    data = pkt[Raw].load
    if not data:
        return None

    if data[0] not in VALID_TLS_CONTENT_BYTES:
        return "traffic on port 443 does not look like valid TLS (unexpected first byte)"
    return None


class TLSRecordTracker:
    """Connection-aware version of the port-443/TLS-byte check.
    Tracks, per TCP connection (5-tuple direction), how many bytes are
    still owed to the TLS record currently in progress. Only checks
    the first-byte rule when a NEW record is actually expected to
    start -- this eliminates the false positives that the simple
    stateless check produces on multi-packet TLS records (a single
    TLS record larger than one packet's MTU gets split across several
    TCP segments; only the first segment legitimately starts with a
    valid TLS type byte).

    Known remaining limitation: assumes packets arrive in order with
    no retransmissions/reordering. Good enough for a normal live
    capture; a production tool would need full TCP reassembly to
    handle out-of-order segments correctly.

    SECURITY: state is capped at MAX_TRACKED_CONNECTIONS entries with
    LRU eviction. Without this, a long-running capture (or an attacker
    opening many short-lived connections) grows this dict forever --
    unbounded memory growth, a real resource-exhaustion risk for a
    tool meant to run continuously.
    """

    MAX_TRACKED_CONNECTIONS = 5000

    def __init__(self):
        self._remaining = OrderedDict()  # (src, sport, dst, dport) -> bytes still owed to current record

    def _conn_key(self, pkt):
        ip, tcp = pkt[IP], pkt[TCP]
        return (ip.src, tcp.sport, ip.dst, tcp.dport)

    def check(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP) or not pkt.haslayer(Raw):
            return None
        if pkt[TCP].sport != 443 and pkt[TCP].dport != 443:
            return None

        data = pkt[Raw].load
        if not data:
            return None

        key = self._conn_key(pkt)
        remaining = self._remaining.get(key, 0)
        self._remaining[key] = remaining  # touch/insert -- marks as most-recently-used
        self._remaining.move_to_end(key)
        if len(self._remaining) > self.MAX_TRACKED_CONNECTIONS:
            self._remaining.popitem(last=False)  # evict least-recently-used

        if remaining > 0:
            # We're still inside a previous record -- consume bytes
            # without checking them, then see if anything is left
            # over (a new record could start later in this same packet).
            consumed = min(remaining, len(data))
            self._remaining[key] = remaining - consumed
            data = data[consumed:]
            if not data:
                return None  # fully consumed by the record in progress

        # At this point `data` should be the start of a NEW record.
        if data[0] not in VALID_TLS_CONTENT_BYTES:
            return "traffic on port 443 does not look like valid TLS (unexpected first byte)"

        if len(data) < 5:
            return None  # header itself got split across packets -- rare, just skip

        record_length = int.from_bytes(data[3:5], "big")
        already_have = len(data) - 5
        self._remaining[key] = max(0, record_length - already_have)
        return None


TLS_MAX_RECORD_LENGTH = 16384  # 2^14, hard protocol limit (RFC 8446)


def check_tls_invalid_length(pkt):
    """Flag a TLS record whose declared length exceeds the protocol
    maximum (16384 bytes). This is a hard spec limit -- unlike
    comparing declared length to captured bytes (which false-positives
    on multi-packet records, see README), a value ABOVE this ceiling
    is never legitimate, regardless of how the record was segmented."""
    tls_info = parse_tls_record(pkt)
    if tls_info is None:
        return None

    if tls_info["record_length"] > TLS_MAX_RECORD_LENGTH:
        return (f"TLS record declares length {tls_info['record_length']} bytes, "
                f"exceeding the protocol maximum of {TLS_MAX_RECORD_LENGTH} "
                f"(malformed or spoofed header)")
    return None


def check_suspicious_dns(pkt, max_length=50):
    """Flag unusually long or high-entropy-looking DNS queries -- a
    common indicator of DNS tunneling (smuggling data through DNS)."""
    domain = parse_dns_query(pkt)
    if domain is None:
        return None

    if len(domain) > max_length:
        return f"unusually long DNS query ({len(domain)} chars): {domain}"

    # crude randomness check: subdomain has very few vowels relative to length
    subdomain = domain.split(".")[0]
    if len(subdomain) > 20:
        vowels = sum(1 for c in subdomain.lower() if c in "aeiou")
        if vowels / len(subdomain) < 0.15:
            return f"high-entropy-looking DNS subdomain: {domain}"

    return None


class PortScanDetector:
    """Tracks SYN packets per source host to flag classic port-scan
    behavior: many SYNs to many different destination ports with few
    or no completed handshakes (SYN-ACK) back.

    SECURITY: state is capped at MAX_TRACKED_HOSTS entries with LRU
    eviction -- without this, a busy network (or an attacker spoofing
    many source IPs) grows this dict forever, an unbounded memory
    growth / resource-exhaustion risk in a tool meant to run for
    extended periods."""

    MAX_TRACKED_HOSTS = 5000

    def __init__(self, port_threshold=10, window_seconds=10):
        self.port_threshold = port_threshold
        self.window_seconds = window_seconds
        self._syn_ports = OrderedDict()  # src_ip -> {"ports": set(), "first_seen": timestamp}

    def check(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return None

        # Use a bitwise check instead of an exact string match ("S").
        # Real-world SYN probes (e.g. from nmap) can carry other flag
        # bits (reserved/ECN bits used for OS fingerprinting evasion)
        # that make flags != "S" fail even though it's still a SYN
        # scan probe. We only require: SYN bit set, ACK bit NOT set --
        # that's the actual definition of a connection-attempt packet.
        flags_int = int(pkt[TCP].flags)
        syn_set = bool(flags_int & 0x02)
        ack_set = bool(flags_int & 0x10)
        if not syn_set or ack_set:
            return None

        src = pkt[IP].src
        dport = pkt[TCP].dport
        now = time.time()

        entry = self._syn_ports.setdefault(src, {"ports": set(), "first_seen": now})
        self._syn_ports.move_to_end(src)
        if len(self._syn_ports) > self.MAX_TRACKED_HOSTS:
            self._syn_ports.popitem(last=False)  # evict least-recently-used host

        if now - entry["first_seen"] > self.window_seconds:
            entry["ports"] = set()
            entry["first_seen"] = now

        entry["ports"].add(dport)

        if len(entry["ports"]) == self.port_threshold:
            return (f"possible port scan from {src}: {len(entry['ports'])} "
                    f"different ports contacted within {self.window_seconds}s")
        return None