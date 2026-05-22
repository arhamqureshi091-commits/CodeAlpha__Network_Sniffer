# 🛡️ CodeAlpha Network Sniffer

## 📌 Overview
This project is Task 1 of the CodeAlpha Cybersecurity Internship. It is an advanced, command-line Network Intrusion & Packet Sniffing tool written in Python. It captures network traffic packets, decodes application-layer protocols, and displays useful information such as source/destination IPs, protocols, and payloads.

## ✨ Features
* **Live Packet Capturing:** Sniffs and analyzes IP packets in real-time.
* **Deep Protocol Decoding:** Identifies HTTP (Web) and DNS (Lookup) traffic alongside standard TCP, UDP, and ICMP protocols.
* **BPF Filtering:** Allows Berkeley Packet Filters (e.g., `tcp port 80`) for highly efficient, targeted sniffing.
* **PCAP Exporting:** Saves captured traffic to a `.pcap` file for further analysis in tools like Wireshark.
* **Live Statistics:** Displays a Wireshark-like summary dashboard when the capture is stopped.
* **Color-Coded UI:** Utilizes `colorama` for a clean, highly readable, professional terminal interface.

## ⚙️ Requirements
* Python 3.x
* `scapy`
* `colorama`
* **Windows Users:** You must have [Npcap](https://npcap.com/) installed in WinPcap API-compatible mode to capture raw packets.

## 🚀 Installation & Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/arhamqureshi091-commits/CodeAlpha__Network_Sniffer.git](https://github.com/arhamqureshi091-commits/CodeAlpha__Network_Sniffer.git)
   cd CodeAlpha__Network_Sniffer

2. Create and activate a virtual environment:

Bash
python -m venv venv
.\venv\Scripts\activate  # On Windows

3. Install the required dependencies:

Bash
pip install -r requirements.txt


💻 Usage
Note: You must run your terminal or command prompt as an Administrator (or root on Linux) for the sniffer to access the network interface.

Basic Capture:

Bash
python sniffer.py
Capture a specific number of packets and save to PCAP:

Bash
python sniffer.py --count 50 --output capture.pcap
Capture only Web Traffic (HTTP) on a specific port:

Bash
python sniffer.py --filter "tcp port 80"


📜 Disclaimer
This tool was created for educational purposes and for the CodeAlpha Internship program. Always ensure you have explicit permission before sniffing traffic on any network.

---
