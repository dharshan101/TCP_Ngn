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
