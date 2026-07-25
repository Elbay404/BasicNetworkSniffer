#!/usr/bin/env python3
"""
Basic Network Sniffer - Raw Socket Version
--------------------------------------------
Educational tool: captures raw packets and manually parses
Ethernet / IP / TCP / UDP / ICMP headers using struct.

Must be run as root (Linux only, uses AF_PACKET).
    sudo python3 raw_sniffer.py
"""

import socket
import struct
import textwrap


def main():
    # AF_PACKET + SOCK_RAW gives us EVERY frame at the Ethernet level,
    # before the OS network stack has touched it.
    # ntohs(0x0003) = ETH_P_ALL -> capture all protocols.
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("[*] Sniffer started. Press Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)

            # SECURITY FIX: never trust bytes from the network. A
            # truncated, malformed, or deliberately crafted frame can
            # be shorter than what struct.unpack expects, which raises
            # struct.error. Without this try/except, ANY single bad
            # packet crashes the entire (root-privileged) sniffer --
            # a trivial denial-of-service for anyone on the segment.
            # We catch, log which stage failed, and keep capturing.
            try:
                eth_proto, dest_mac, src_mac, eth_data = unpack_ethernet(raw_data)
            except struct.error:
                print("[!] Skipped a malformed/truncated Ethernet frame")
                continue

            print(f"\nEthernet Frame:")
            print(f"  Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

            # 8 = IPv4 EtherType
            if eth_proto == 8:
                try:
                    (version, header_len, ttl, proto, src_ip, target_ip, ip_data) = unpack_ipv4(eth_data)
                except (struct.error, IndexError):
                    print("  [!] Skipped a malformed IPv4 header")
                    continue
                print(f"  IPv4 Packet:")
                print(f"    Version: {version}, Header Length: {header_len}, TTL: {ttl}")
                print(f"    Protocol: {proto}, Source IP: {src_ip}, Destination IP: {target_ip}")

                try:
                    # TCP
                    if proto == 6:
                        (src_port, dest_port, sequence, ack, flags, payload) = unpack_tcp(ip_data)
                        print(f"    TCP Segment:")
                        print(f"      Source Port: {src_port}, Destination Port: {dest_port}")
                        print(f"      Sequence: {sequence}, Acknowledgment: {ack}")
                        print(f"      Flags: {flags}")
                        print(f"      Payload:\n{format_payload(payload)}")

                    # UDP
                    elif proto == 17:
                        src_port, dest_port, length, payload = unpack_udp(ip_data)
                        print(f"    UDP Segment:")
                        print(f"      Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}")
                        print(f"      Payload:\n{format_payload(payload)}")

                    # ICMP
                    elif proto == 1:
                        icmp_type, code, checksum, payload = unpack_icmp(ip_data)
                        print(f"    ICMP Packet:")
                        print(f"      Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                        print(f"      Payload:\n{format_payload(payload)}")

                    else:
                        print(f"    Other IPv4 protocol (number {proto}), raw data:")
                        print(format_payload(ip_data))
                except struct.error:
                    print(f"    [!] Skipped a malformed transport-layer segment (protocol {proto})")
                    continue

    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer.")
        conn.close()


def unpack_ethernet(data):
    """Ethernet header is fixed at 14 bytes:
    6 bytes dest MAC, 6 bytes src MAC, 2 bytes EtherType."""
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return socket.htons(proto), format_mac(dest_mac), format_mac(src_mac), data[14:]


def format_mac(bytes_addr):
    return ":".join(f"{b:02x}" for b in bytes_addr)


def unpack_ipv4(data):
    """First byte packs (version:4bits, header_length:4bits)."""
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4  # in 32-bit words -> bytes

    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_len, ttl, proto, format_ip(src), format_ip(target), data[header_len:]


def format_ip(bytes_addr):
    return ".".join(map(str, bytes_addr))


def unpack_tcp(data):
    """TCP header: src port, dest port, seq, ack, then offset+flags."""
    (src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack("! H H L L H", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    flags = f"URG={flag_urg} ACK={flag_ack} PSH={flag_psh} RST={flag_rst} SYN={flag_syn} FIN={flag_fin}"
    return src_port, dest_port, sequence, ack, flags, data[offset:]


def unpack_udp(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]


def unpack_icmp(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]


def is_mostly_printable(text, threshold=0.95):
    """Check that decoded text is actually human-readable, not just
    technically valid UTF-8. Some binary/encrypted data happens to
    decode as UTF-8 by coincidence, dumping raw control characters
    into the terminal (which confuses tools like grep). We require
    almost all characters to be printable or common whitespace."""
    if not text:
        return True
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return (printable / len(text)) >= threshold


def format_payload(data, max_bytes=96):
    """Print payload as readable text if possible, else hex, truncated."""
    data = data[:max_bytes]
    try:
        text = data.decode("utf-8")
        if not is_mostly_printable(text):
            raise UnicodeDecodeError("utf-8", data, 0, 1, "decoded but not printable")
        wrapped = textwrap.fill(text, width=64, initial_indent="        ", subsequent_indent="        ")
        return wrapped if text.strip() else "        (empty)"
    except UnicodeDecodeError:
        hex_str = " ".join(f"{b:02x}" for b in data)
        return textwrap.fill(hex_str, width=64, initial_indent="        ", subsequent_indent="        ")


if __name__ == "__main__":
    main()