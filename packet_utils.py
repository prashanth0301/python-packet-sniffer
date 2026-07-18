"""
Packet Utilities
Handles:
- Logging
- Statistics
- Capture Timer
- Packet Counter
"""

import os
import time

from config import OUTPUT_FILE, GREEN, CYAN, RESET

# ---------------------------------------
# Statistics
# ---------------------------------------

statistics = {
    "TCP": 0,
    "UDP": 0,
    "DNS": 0,
    "ICMP": 0,
    "ARP": 0,
    "OTHER": 0
}

packet_number = 0
capture_start_time = None


# ---------------------------------------
# Initialize Output File
# ---------------------------------------

def initialize_output():

    os.makedirs("output", exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:

        file.write("=" * 70 + "\n")
        file.write("PYTHON PACKET SNIFFER LOG\n")
        file.write("=" * 70 + "\n\n")


# ---------------------------------------
# Start Timer
# ---------------------------------------

def start_capture():

    global capture_start_time

    capture_start_time = time.time()


# ---------------------------------------
# Packet Counter
# ---------------------------------------

def next_packet():

    global packet_number

    packet_number += 1

    return packet_number


# ---------------------------------------
# Increment Statistics
# ---------------------------------------

def increment(protocol):

    protocol = protocol.upper()

    if protocol in statistics:

        statistics[protocol] += 1

    else:

        statistics["OTHER"] += 1


# ---------------------------------------
# Save Packet
# ---------------------------------------

def save_packet(text):

    with open(OUTPUT_FILE, "a", encoding="utf-8") as file:

        file.write(text)
        file.write("\n")
        file.write("-" * 70)
        file.write("\n\n")


# ---------------------------------------
# Capture Duration
# ---------------------------------------

def capture_duration():

    if capture_start_time is None:

        return 0

    return round(time.time() - capture_start_time, 2)


# ---------------------------------------
# Packets Per Second
# ---------------------------------------

def packet_rate():

    duration = capture_duration()

    if duration == 0:

        return 0

    return round(packet_number / duration, 2)


# ---------------------------------------
# Print Final Statistics
# ---------------------------------------

def print_statistics():

    print()

    print(CYAN + "=" * 70)

    print(GREEN + "Capture Summary")

    print(CYAN + "=" * 70)

    print(f"Capture Duration : {capture_duration()} Seconds")

    print(f"Packets Captured : {packet_number}")

    print(f"Packet Rate      : {packet_rate()} Packets/sec")

    print()

    for protocol, count in statistics.items():

        print(f"{protocol:<10}: {count}")

    print()

    print(f"Output File : {OUTPUT_FILE}")

    print(CYAN + "=" * 70 + RESET)