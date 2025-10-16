#!/usr/bin/env python3
"""Offline traffic generator for NETS test scenarios."""
import argparse
import random
import socket
import time
from typing import Optional

from scapy.all import Ether, ARP, DNS, DNSQR, IP, TCP, UDP, sendp, wrpcap  # type: ignore

SCENARIOS = {"dns-nx-spike", "arp-spoof", "smb-burst", "listener"}


def generate_dns_nx(count: int, iface: str, capture: Optional[str] = None) -> None:
    packets = []
    for _ in range(count):
        domain = f"{random.randint(1, 10_000)}.example.test"
        pkt = (
            IP(src="10.0.0.5", dst="10.0.0.53")
            / UDP(sport=random.randint(1024, 65535), dport=53)
            / DNS(id=random.randint(0, 65535), rd=1, qd=DNSQR(qname=domain))
        )
        packets.append(pkt)
    if capture:
        wrpcap(capture, packets)
    else:
        for pkt in packets:
            sendp(pkt, iface=iface, verbose=False)


def generate_arp_spoof(iface: str, capture: Optional[str] = None) -> None:
    arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="10.0.0.1", hwsrc="de:ad:be:ef:00:01")
    if capture:
        wrpcap(capture, [arp])
    else:
        sendp(arp, iface=iface, verbose=False)


def generate_smb_burst(iface: str, capture: Optional[str] = None) -> None:
    packets = []
    for port in (445, 139):
        pkt = IP(src="10.0.0.9", dst="10.0.0.10") / TCP(sport=50000, dport=port, flags="S")
        packets.append(pkt)
    if capture:
        wrpcap(capture, packets)
    else:
        for pkt in packets:
            sendp(pkt, iface=iface, verbose=False)


def simulate_listener(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", port))
    sock.listen()
    print(f"Listener running on {port}, press Ctrl+C to exit")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True, choices=SCENARIOS)
    parser.add_argument("--iface", default="lo")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--capture")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    if args.scenario == "dns-nx-spike":
        generate_dns_nx(args.count, args.iface, args.capture)
    elif args.scenario == "arp-spoof":
        generate_arp_spoof(args.iface, args.capture)
    elif args.scenario == "smb-burst":
        generate_smb_burst(args.iface, args.capture)
    elif args.scenario == "listener":
        simulate_listener(args.port)


if __name__ == "__main__":
    main()
