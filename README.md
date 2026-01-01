# Network Traffic Monitoring & Intrusion Detection Tool

A Python-based network traffic monitoring and intrusion detection system (IDS)
that captures live TCP/IP traffic and detects potential port scanning activity
using TCP SYN packet analysis.

This project demonstrates core intrusion detection concepts such as packet
inspection, rule-based detection, and alert logging on a Windows system.

---

## Features
- Live TCP packet capture using Scapy
- Detection of port scanning behavior based on SYN packets
- Real-time alerts displayed in the terminal
- Persistent alert logging with timestamps
- Windows-compatible using Npcap
- Simple rule-based detection logic (easy to extend)

---

## Tech Stack
- **Python**
- **Scapy**
- **TCP/IP**
- **Npcap (Windows)**
- **Git & GitHub**

---

## Project Structure


network-traffic-ids/
├── src/
│ └── port_scan_detector.py
├── logs/
│ └── alerts.log
├── README.md
├── requirements.txt
└── .gitignore


---

## How It Works
1. Captures live TCP packets from the active network interface.
2. Monitors TCP SYN packets to identify connection attempts.
3. Tracks the number of unique destination ports accessed by each source IP.
4. Flags a potential port scan when a threshold is exceeded within a time window.
5. Generates alerts and writes them to a log file.

---

## Installation

### Prerequisites
- Python 3.8+
- Wireshark with **Npcap** installed  
  (WinPcap-compatible mode enabled)
- Administrator privileges (required for packet capture)

### Install dependencies
```bash
pip install -r requirements.txt

Usage

Run the IDS (Command Prompt as Administrator):

python src/port_scan_detector.py


Trigger network activity using tools like:

nmap -sT -p 80,81,82 <target-ip>

Alerts & Logs

Alerts are printed directly in the terminal.

Alerts are also stored persistently in:

logs/alerts.log


Example log entry:

[2026-01-01 15:02:11] PORT SCAN DETECTED | Source=8.8.8.8 | Ports={51384, 5693, 53390}

Notes

Loopback traffic (127.0.0.1) is not captured by default on Windows.

Detection works on real network interfaces.

Detection thresholds are intentionally low for demonstration purposes.

This project focuses on learning IDS fundamentals, not production deployment.

Future Improvements

Protocol-specific detection rules

Rate-based anomaly detection

Email / webhook alerting

Dashboard visualization

Multi-threaded packet processing

Author

Sarvesh Shiva Sharan
Electronics & Communication Engineering