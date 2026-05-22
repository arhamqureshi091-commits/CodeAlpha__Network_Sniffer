#!/usr/bin/env python3
"""
Advanced Network Sniffer - CodeAlpha Internship

Features:
- BPF Filtering for high efficiency
- Deep Protocol Decoding (HTTP & DNS)
- PCAP Exporting
- Live Capture Statistics Summary
"""

import argparse
import sys
import textwrap
from datetime import datetime

# Import scapy networking primitives
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS
from scapy.layers.http import HTTPRequest
from scapy.utils import PcapWriter

# colorama for terminal colors
from colorama import init as colorama_init, Fore, Style

colorama_init()

def print_banner():
    """Prints a professional ASCII art banner."""
    banner = f"""
{Fore.CYAN}
   ____          _         _         _       _           
  / ___|___   __| | ___   / \   _ __| |__   / \    _ __  
 | |   / _ \ / _` |/ _ \ / _ \ | '__| '_ \ / _ \  | '_ \ 
 | |__| (_) | (_| |  __// ___ \| |  | |_) / ___ \ | |_) |
  \____\___/ \__,_|\___/_/   \_\_|  |_.__/_/   \_\| .__/ 
                                                  |_|    
{Fore.YELLOW}  --- Network Sniffer v2.0 (CodeAlpha Internship) ---
{Style.RESET_ALL}
    """
    print(banner)

def parse_arguments():
    """Parse command-line arguments, including BPF filters."""
    parser = argparse.ArgumentParser(
        prog="sniffer.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Advanced CLI Network Sniffer",
    )

    parser.add_argument("-i", "--interface", help="Network interface to capture on", default=None)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (0 for infinite)", default=0)
    parser.add_argument("-o", "--output", help="Save captured packets to a .pcap file", default=None)
    # NEW FEATURE: Berkeley Packet Filter (BPF) for efficiency
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80' or 'udp')", default="")

    return parser.parse_args()

# Colors
TCP_COLOR = Fore.CYAN
UDP_COLOR = Fore.GREEN
ICMP_COLOR = Fore.MAGENTA
HTTP_COLOR = Fore.RED
DNS_COLOR = Fore.BLUE
OTHER_COLOR = Fore.YELLOW
RESET = Style.RESET_ALL

def _format_payload_snippet(raw_bytes, max_len=50):
    """Return a short human-readable snippet for raw payload bytes."""
    if not raw_bytes:
        return ""
    snippet = raw_bytes[:max_len]
    try:
        text = snippet.decode("utf-8", errors="ignore")
        visible = text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        return visible + "..." if len(raw_bytes) > max_len else visible
    except Exception:
        return f"0x{snippet.hex()}" + ("..." if len(raw_bytes) > max_len else "")

def get_packet_processor(pcap_writer, stats_dict):
    """Processes packets, saves to PCAP, and updates live statistics."""
    def process_packet(pkt):
        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        
        proto_name = "OTHER"
        color = OTHER_COLOR
        extra_info = ""

        # Deep Decoding: Check Application Layer First
        if pkt.haslayer(HTTPRequest):
            proto_name = "HTTP"
            color = HTTP_COLOR
            stats_dict["HTTP"] += 1
            # Extract the website host requested
            host = pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else "Unknown"
            extra_info = f" [Host: {host}]"
            
        elif pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0: # qr==0 means it's a query
            proto_name = "DNS"
            color = DNS_COLOR
            stats_dict["DNS"] += 1
            # Extract the website being looked up
            qname = pkt.getlayer(DNS).qd.qname.decode() if pkt.getlayer(DNS).qd else "Unknown"
            extra_info = f" [Query: {qname}]"

        # Basic Transport Layer
        elif pkt.haslayer(TCP):
            proto_name = "TCP"
            color = TCP_COLOR
            stats_dict["TCP"] += 1
        elif pkt.haslayer(UDP):
            proto_name = "UDP"
            color = UDP_COLOR
            stats_dict["UDP"] += 1
        elif pkt.haslayer(ICMP):
            proto_name = "ICMP"
            color = ICMP_COLOR
            stats_dict["ICMP"] += 1
        else:
            stats_dict["OTHER"] += 1

        stats_dict["TOTAL"] += 1

        payload_snippet = ""
        if pkt.haslayer(Raw) and proto_name not in ["HTTP", "DNS"]:
            raw_bytes = bytes(pkt[Raw].load)
            payload_snippet = _format_payload_snippet(raw_bytes)

        ts = datetime.now().strftime("%H:%M:%S")

        # Print the packet line
        print(f"{color}[{ts}] {src} -> {dst} | {proto_name}{extra_info} | {payload_snippet}{RESET}")

        if pcap_writer:
            pcap_writer.write(pkt)

    return process_packet

def print_statistics(stats):
    """Prints a summary table when the script ends."""
    print(f"\n{Fore.MAGENTA}=========================================")
    print(f"      CAPTURE STATISTICS SUMMARY         ")
    print(f"========================================={RESET}")
    print(f" Total Packets Captured : {stats['TOTAL']}")
    print(f"-----------------------------------------")
    print(f" {Fore.CYAN}TCP Packets          : {stats['TCP']}{RESET}")
    print(f" {Fore.GREEN}UDP Packets          : {stats['UDP']}{RESET}")
    print(f" {Fore.MAGENTA}ICMP (Ping) Packets  : {stats['ICMP']}{RESET}")
    print(f" {Fore.RED}HTTP (Web) Packets   : {stats['HTTP']}{RESET}")
    print(f" {Fore.BLUE}DNS (Lookup) Packets : {stats['DNS']}{RESET}")
    print(f" {Fore.YELLOW}Other IP Packets     : {stats['OTHER']}{RESET}")
    print(f"{Fore.MAGENTA}========================================={RESET}\n")

def main():
    print_banner()
    args = parse_arguments()

    iface = args.interface
    count = args.count if args.count >= 0 else 0
    pcap_file = args.output
    bpf_filter = args.filter

    # Dictionary to hold our live statistics
    stats = {"TOTAL": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0, "DNS": 0, "OTHER": 0}

    pcap_writer = None
    if pcap_file:
        try:
            pcap_writer = PcapWriter(pcap_file, append=True, sync=True)
            print(f"{Fore.YELLOW}[*] Saving PCAP to: {pcap_file}{RESET}")
        except PermissionError:
            print(f"{Fore.RED}[!] Permission denied to write PCAP. Run as Admin.{RESET}")
            sys.exit(1)

    if bpf_filter:
        print(f"{Fore.YELLOW}[*] BPF Filter Active: '{bpf_filter}'{RESET}")

    print(f"{Fore.GREEN}[*] Listening on interface: {iface if iface else 'Default'}{RESET}")
    print("Press Ctrl+C to stop capture and view statistics...\n")

    packet_callback = get_packet_processor(pcap_writer, stats)

    try:
        # sniff() now includes the filter= argument for maximum efficiency
        sniff(iface=iface, prn=packet_callback, count=count or 0, store=False, filter=bpf_filter)
    except PermissionError:
        sys.stderr.write(f"{Fore.RED}[!] Permission denied: Must run as Administrator/Root.{RESET}\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"{Fore.RED}[!] An error occurred: {e}{RESET}\n")
    except KeyboardInterrupt:
        pass # Catch the Ctrl+C silently so we can print the stats
    finally:
        if pcap_writer:
            pcap_writer.close()
            print(f"\n{Fore.YELLOW}[*] PCAP file saved successfully.{RESET}")
        
        # Print the final summary table
        print_statistics(stats)
        sys.exit(0)

if __name__ == "__main__":
    main()