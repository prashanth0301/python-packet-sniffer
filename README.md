# Python Packet Sniffer

A beginner-friendly packet sniffer developed using Python and Scapy. The project captures live network packets from a selected network interface and displays protocol information in real time.

---

## Features

- Capture live network packets
- Interface selection
- Capture filters
  - All
  - TCP
  - UDP
  - ICMP
  - DNS
- TCP, UDP, DNS, ICMP and ARP parsing
- Source and Destination IP
- Source and Destination MAC
- TCP Flag decoding
- Service name detection
- Incoming/Outgoing packet detection
- Packet numbering
- Timestamp
- Capture statistics
- Log packets to file
- Colored console output
- Graceful exit using Ctrl+C

---

## Technologies Used

- Python
- Scapy
- Colorama

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Run

```bash
python packet_sniffer.py
```

---

## Project Structure

```
Python-Packet-Sniffer/

├── packet_sniffer.py
├── protocols.py
├── packet_utils.py
├── interface_manager.py
├── banner.py
├── config.py
│
├── output/
│
├── assets/
│
├── README.md
├── notes.md
├── requirements.txt
└── .gitignore
```

---

## Sample Output

```
Packet #15

Protocol : TCP

Source IP : 192.168.0.101

Destination IP : 142.250.xxx.xxx

Source Port : 53425

Destination Port : 443

Service : HTTPS

TCP Flags : ACK
```

---

## Skills Demonstrated

- Python Programming
- Network Programming
- Packet Analysis
- Protocol Parsing
- Modular Programming
- File Handling
- Exception Handling

---

## Future Improvements

- IPv6 support
- Save packets to PCAP
- CSV export
- GUI using Tkinter or PyQt
- Packet search
- Advanced filters

---

## Author

Prashanth Reddy