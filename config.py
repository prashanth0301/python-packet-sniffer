"""
Configuration File
Python Packet Sniffer v2.0
"""

from colorama import Fore, Style

# -----------------------------
# Output File
# -----------------------------
OUTPUT_FILE = "output/captured_packets.txt"

# -----------------------------
# Colors
# -----------------------------
GREEN = Fore.GREEN
RED = Fore.RED
BLUE = Fore.BLUE
CYAN = Fore.CYAN
YELLOW = Fore.YELLOW
MAGENTA = Fore.MAGENTA
WHITE = Fore.WHITE
RESET = Style.RESET_ALL

# -----------------------------
# Common Service Names
# -----------------------------
COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy"
}

# -----------------------------
# Packet Filters
# -----------------------------
FILTERS = {
    "1": ("All Packets", ""),
    "2": ("TCP Only", "tcp"),
    "3": ("UDP Only", "udp"),
    "4": ("ICMP Only", "icmp"),
    "5": ("DNS Only", "port 53")
}