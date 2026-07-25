#!/usr/bin/env python3
"""
Basic Network Sniffer - main entry point
--------------------------------------------
Captures live packets and displays: Source IP, Destination IP,
Protocol, Ports (if applicable), and Payload preview.

Requires: pip install -r requirements.txt
Run as root (needed for raw socket access):
    sudo venv/bin/python3 main.py
    sudo venv/bin/python3 main.py -i eth0 -f "tcp port 80" -c 20
"""

import argparse
from datetime import datetime
from functools import partial

from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.utils import PcapWriter

from utils import (
    describe_protocol,
    format_payload,
    parse_tls_record,
    parse_dns_query,
    check_plaintext_credentials,
    check_tls_invalid_length,
    check_suspicious_dns,
    PortScanDetector,
    TLSRecordTracker,
)


def handle_packet(pkt, show_tls=False, show_dns=False, detect=False,
                   scan_detector=None, tls_tracker=None, pcap_writer=None):
    """Callback executed for every captured packet."""
    if not pkt.haslayer(IP):
        return  # skip non-IP traffic (e.g. ARP) for this basic version

    if pcap_writer is not None:
        pcap_writer.write(pkt)  # save the raw packet to disk, unmodified

    ip_layer = pkt[IP]
    proto = describe_protocol(pkt)
    timestamp = datetime.now().strftime("%H:%M:%S")

    line = f"[{timestamp}] {ip_layer.src} -> {ip_layer.dst} | {proto}"

    if pkt.haslayer(TCP):
        line += f" | {pkt[TCP].sport} -> {pkt[TCP].dport} | flags={pkt[TCP].flags}"
    elif pkt.haslayer(UDP):
        line += f" | {pkt[UDP].sport} -> {pkt[UDP].dport}"
    elif pkt.haslayer(ICMP):
        line += f" | type={pkt[ICMP].type} code={pkt[ICMP].code}"

    print(line)

    payload = format_payload(pkt)
    if payload is not None:
        print(f"    Payload: {payload!r}")

    # --- optional decoders, off by default ---
    if show_tls:
        tls_info = parse_tls_record(pkt)
        if tls_info:
            print(f"    TLS: {tls_info['content_type']} | {tls_info['version']} "
                  f"| record length={tls_info['record_length']}")

    if show_dns:
        domain = parse_dns_query(pkt)
        if domain:
            print(f"    DNS query: {domain}")

    # --- optional detection heuristics, off by default ---
    if detect:
        for alert in (
            check_plaintext_credentials(pkt),
            tls_tracker.check(pkt) if tls_tracker else None,
            check_tls_invalid_length(pkt),
            check_suspicious_dns(pkt),
            scan_detector.check(pkt) if scan_detector else None,
        ):
            if alert:
                print(f"    [ALERT] {alert}")

    print()  # blank line between packets for readability


def main():
    parser = argparse.ArgumentParser(description="Basic Python packet sniffer (Scapy).")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: all)")
    parser.add_argument("-f", "--filter", help="BPF filter, e.g. 'tcp port 80' or 'icmp'", default="")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("--show-tls", action="store_true",
                         help="Decode and display the TLS record header (content type, version, length) when present")
    parser.add_argument("--show-dns", action="store_true",
                         help="Decode and display the queried domain name for DNS queries")
    parser.add_argument("--detect", action="store_true",
                         help="Enable lightweight suspicious-activity alerts (plaintext creds, "
                              "TLS/port mismatch, suspicious DNS, port-scan pattern)")
    parser.add_argument("--pcap", metavar="FILE",
                         help="Save captured packets to a pcap file (e.g. --pcap capture.pcap), "
                              "viewable later in Wireshark")
    args = parser.parse_args()

    print("[*] Starting sniffer. Press Ctrl+C to stop.")
    if args.filter:
        print(f"[*] Filter: {args.filter}")
    if args.detect:
        print("[*] Detection heuristics enabled")

    scan_detector = PortScanDetector() if args.detect else None
    tls_tracker = TLSRecordTracker() if args.detect else None

    pcap_writer = None
    if args.pcap:
        pcap_writer = PcapWriter(args.pcap, append=False, sync=True)
        print(f"[*] Saving capture to: {args.pcap}")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter if args.filter else None,
            prn=partial(handle_packet, show_tls=args.show_tls, show_dns=args.show_dns,
                        detect=args.detect, scan_detector=scan_detector,
                        tls_tracker=tls_tracker, pcap_writer=pcap_writer),
            count=args.count,
            store=False,
        )
    finally:
        if pcap_writer is not None:
            pcap_writer.close()
            print(f"\n[*] Capture saved to {args.pcap}")


if __name__ == "__main__":
    main()