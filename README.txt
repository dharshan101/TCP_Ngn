This script:

Uses Scapy to sniff TCP packets from the network.

Filters out non-TCP packets.

Prints source/destination IP addresses and ports.

Runs continuously until the user interrupts it with Ctrl+C.


# TCP Packet Sniffer

A simple Python-based TCP packet sniffer using the [Scapy](https://scapy.net/) library.

##  Features

- Captures live TCP packets from the local network.
- Extracts and displays:
  - Source IP and port
  - Destination IP and port
- Real-time output
- Clean and simple code

---

##  Requirements

- Python 3.7 or higher
- Administrator/root privileges (required for packet sniffing)
- Scapy library

##  Installation

1. **Install Python**  
   Download and install from: https://www.python.org/downloads/

2. **Install Scapy**  
   Open terminal/command prompt and run:

   pip install scapy

from scapy.all import sniff, TCP, IP
def process_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_address_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        src_ip = ip_address_layer.src
        dst_ip = ip_address_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        print(f"[+] TCP Packet: {src_ip}:{src_port} >>>>>> {dst_ip}:{dst_port}")

def main():
 
    print("[*] Starting TCP packet sniffer... Press Ctrl+C to stop.")
    
    try:
        sniff(filter="tcp", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping packet sniffer.")

if __name__ == "__main__":
    main()

Output Format:
[+] TCP Packet: 192.168.0.2:443 >>>>>> 192.168.0.10:56832
