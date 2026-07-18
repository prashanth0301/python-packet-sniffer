from colorama import init
from config import CYAN, YELLOW, RESET

init(autoreset=True)


def display_banner():

    print(CYAN + "=" * 70)

    print(YELLOW + r"""
   _____       _   _        __  __
  |  __ \     | | | |      |  \/  |
  | |__) |   _| |_| |_ ___ | \  / | ___
  |  ___/ | | | __| __/ _ \| |\/| |/ _ \
  | |   | |_| | |_| || (_) | |  | |  __/
  |_|    \__, |\__|\__\___/|_|  |_|\___|
           __/ |
          |___/

        Python Packet Sniffer v2.0
    """)

    print(CYAN + "=" * 70 + RESET)