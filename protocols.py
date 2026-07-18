"""
Protocol Handlers
"""

import socket
from datetime import datetime

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import ARP, Ether

from packet_utils import next_packet, increment, save_packet

from config import (
    COMMON_PORTS,
    GREEN,
    CYAN,
    BLUE,
    YELLOW,
    MAGENTA,
    RESET
)

# -----------------------------------------------------
# Local IP
# -----------------------------------------------------

try:
    LOCAL_IP = socket.gethostbyname(socket.gethostname())
except:
    LOCAL_IP = ""


# -----------------------------------------------------
# Hostname Lookup
# -----------------------------------------------------

def hostname(ip):

    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"


# -----------------------------------------------------
# Service Name
# -----------------------------------------------------

def service_name(port):

    return COMMON_PORTS.get(port, "Unknown")


# -----------------------------------------------------
# TCP Flags
# -----------------------------------------------------

def tcp_flags(flag):

    flags = []

    if flag & 0x01:
        flags.append("FIN")

    if flag & 0x02:
        flags.append("SYN")

    if flag & 0x04:
        flags.append("RST")

    if flag & 0x08:
        flags.append("PSH")

    if flag & 0x10:
        flags.append("ACK")

    if flag & 0x20:
        flags.append("URG")

    if flag & 0x40:
        flags.append("ECE")

    if flag & 0x80:
        flags.append("CWR")

    return ", ".join(flags)


# -----------------------------------------------------
# Direction
# -----------------------------------------------------

def direction(source_ip):

    if source_ip == LOCAL_IP:
        return "Outgoing"

    return "Incoming"


# -----------------------------------------------------
# Packet Header
# -----------------------------------------------------

def packet_header(protocol):

    number = next_packet()

    return (
        f"\n{'=' * 70}\n"
        f"Packet #{number}\n"
        f"Time            : {datetime.now().strftime('%H:%M:%S')}\n"
        f"Protocol        : {protocol}\n"
    )


# -----------------------------------------------------
# TCP
# -----------------------------------------------------

def parse_tcp(packet):

    increment("TCP")

    ethernet = packet[Ether]
    ip = packet[IP]
    tcp = packet[TCP]

    text = (
        packet_header("TCP") +

        f"Direction       : {direction(ip.src)}\n\n"

        f"Source MAC      : {ethernet.src}\n"
        f"Destination MAC : {ethernet.dst}\n\n"

        f"Source IP       : {ip.src}\n"
        f"Destination IP  : {ip.dst}\n"

        f"Source Host     : {hostname(ip.src)}\n"
        f"Destination Host: {hostname(ip.dst)}\n\n"

        f"Source Port     : {tcp.sport}\n"
        f"Destination Port: {tcp.dport}\n"

        f"Service         : {service_name(tcp.dport)}\n"

        f"TCP Flags       : {tcp_flags(tcp.flags)}\n"

        f"Packet Length   : {len(packet)} Bytes\n"

        f"{'=' * 70}"
    )

    print(GREEN + text + RESET)

    save_packet(text)


# -----------------------------------------------------
# UDP
# -----------------------------------------------------

def parse_udp(packet):

    increment("UDP")

    ethernet = packet[Ether]
    ip = packet[IP]
    udp = packet[UDP]

    text = (
        packet_header("UDP") +

        f"Direction       : {direction(ip.src)}\n\n"

        f"Source MAC      : {ethernet.src}\n"
        f"Destination MAC : {ethernet.dst}\n\n"

        f"Source IP       : {ip.src}\n"
        f"Destination IP  : {ip.dst}\n"

        f"Source Host     : {hostname(ip.src)}\n"
        f"Destination Host: {hostname(ip.dst)}\n\n"

        f"Source Port     : {udp.sport}\n"
        f"Destination Port: {udp.dport}\n"

        f"Service         : {service_name(udp.dport)}\n"

        f"Packet Length   : {len(packet)} Bytes\n"

        f"{'=' * 70}"
    )

    print(BLUE + text + RESET)

    save_packet(text)

# -----------------------------------------------------
# DNS
# -----------------------------------------------------

def parse_dns(packet):

    increment("DNS")

    ethernet = packet[Ether]
    ip = packet[IP]
    udp = packet[UDP]
    dns = packet[DNS]

    query = "Unknown"

    if dns.qd and isinstance(dns.qd, DNSQR):
        query = dns.qd.qname.decode(errors="ignore")

    text = (
        packet_header("DNS") +

        f"Direction       : {direction(ip.src)}\n\n"

        f"Source MAC      : {ethernet.src}\n"
        f"Destination MAC : {ethernet.dst}\n\n"

        f"Source IP       : {ip.src}\n"
        f"Destination IP  : {ip.dst}\n\n"

        f"Source Port     : {udp.sport}\n"
        f"Destination Port: {udp.dport}\n"

        f"DNS Query       : {query}\n"

        f"Packet Length   : {len(packet)} Bytes\n"

        f"{'=' * 70}"
    )

    print(MAGENTA + text + RESET)

    save_packet(text)


# -----------------------------------------------------
# ICMP
# -----------------------------------------------------

def parse_icmp(packet):

    increment("ICMP")

    ethernet = packet[Ether]
    ip = packet[IP]
    icmp = packet[ICMP]

    text = (
        packet_header("ICMP") +

        f"Direction       : {direction(ip.src)}\n\n"

        f"Source MAC      : {ethernet.src}\n"
        f"Destination MAC : {ethernet.dst}\n\n"

        f"Source IP       : {ip.src}\n"
        f"Destination IP  : {ip.dst}\n"

        f"ICMP Type       : {icmp.type}\n"
        f"ICMP Code       : {icmp.code}\n"

        f"Packet Length   : {len(packet)} Bytes\n"

        f"{'=' * 70}"
    )

    print(CYAN + text + RESET)

    save_packet(text)


# -----------------------------------------------------
# ARP
# -----------------------------------------------------

def parse_arp(packet):

    increment("ARP")

    ethernet = packet[Ether]
    arp = packet[ARP]

    operation = "Request"

    if arp.op == 2:
        operation = "Reply"

    text = (
        packet_header("ARP") +

        f"Operation       : {operation}\n\n"

        f"Source MAC      : {ethernet.src}\n"
        f"Destination MAC : {ethernet.dst}\n\n"

        f"Sender IP       : {arp.psrc}\n"
        f"Target IP       : {arp.pdst}\n"

        f"Sender MAC      : {arp.hwsrc}\n"
        f"Target MAC      : {arp.hwdst}\n"

        f"Packet Length   : {len(packet)} Bytes\n"

        f"{'=' * 70}"
    )

    print(YELLOW + text + RESET)

    save_packet(text)


# -----------------------------------------------------
# Packet Dispatcher
# -----------------------------------------------------

def analyze_packet(packet):

    try:

        if packet.haslayer(ARP):

            parse_arp(packet)

            return

        if not packet.haslayer(IP):

            return

        if packet.haslayer(DNS):

            parse_dns(packet)

        elif packet.haslayer(TCP):

            parse_tcp(packet)

        elif packet.haslayer(UDP):

            parse_udp(packet)

        elif packet.haslayer(ICMP):

            parse_icmp(packet)

        else:

            increment("OTHER")

    except Exception as error:

        print(f"Packet Error : {error}")