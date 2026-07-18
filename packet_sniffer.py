"""
Python Packet Sniffer v2.0
Main Program
"""

from colorama import init
from scapy.all import sniff

from banner import display_banner
from interface_manager import select_interface
from protocols import analyze_packet

from packet_utils import (
    initialize_output,
    start_capture,
    print_statistics
)

from config import FILTERS, CYAN, GREEN, RED, RESET

init(autoreset=True)


# -----------------------------------------------------
# Filter Selection
# -----------------------------------------------------

def select_filter():

    print(CYAN + "\nCapture Filters\n")

    for key, value in FILTERS.items():

        print(f"[{key}] {value[0]}")

    while True:

        choice = input("\nSelect Filter : ")

        if choice in FILTERS:

            return FILTERS[choice]

        print(RED + "Invalid choice. Try again.\n")


# -----------------------------------------------------
# Start Capture
# -----------------------------------------------------

def start_sniffer(interface, capture_filter):

    print(GREEN + "\nStarting Packet Capture...")
    print(f"Interface : {interface}")

    if capture_filter:
        print(f"Filter    : {capture_filter}")
    else:
        print("Filter    : None")

    print("\nPress CTRL+C to stop.\n")

    sniff(
        iface=interface,
        filter=capture_filter,
        prn=analyze_packet,
        store=False
    )


# -----------------------------------------------------
# Main
# -----------------------------------------------------

def main():

    display_banner()

    initialize_output()

    interface = select_interface()

    filter_name, filter_rule = select_filter()

    print(f"\nSelected Filter : {filter_name}")

    start_capture()

    try:

        start_sniffer(interface, filter_rule)

    except KeyboardInterrupt:

        print(RED + "\n\nCapture Stopped by User.\n")

    finally:

        print_statistics()


if __name__ == "__main__":

    main()