"""
Interface Manager
"""

from scapy.all import IFACES
from config import CYAN, GREEN, RED, RESET


def get_interfaces():

    interfaces = []

    for interface in IFACES.values():

        if interface.ip:

            interfaces.append(interface)

    return interfaces


def display_interfaces(interfaces):

    print(CYAN + "\nAvailable Network Interfaces\n")

    for index, interface in enumerate(interfaces, start=1):

        print(f"{GREEN}[{index}] {interface.name}")

        if interface.description:
            print(f"     {interface.description}")

        if interface.ip:
            print(f"     IP : {interface.ip}")

        print()


def select_interface():

    interfaces = get_interfaces()

    if not interfaces:
        print(RED + "No usable network interfaces found.")
        exit()

    display_interfaces(interfaces)

    while True:

        try:

            choice = int(input(CYAN + "Select Interface : "))

            if 1 <= choice <= len(interfaces):

                selected = interfaces[choice - 1]

                print(GREEN + f"\nUsing Interface : {selected.name}\n")

                return selected.name

            print(RED + "Invalid selection.\n")

        except ValueError:

            print(RED + "Enter a valid number.\n")