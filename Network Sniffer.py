from scapy.all import sniff, IP, TCP, UDP, Raw

def analyze_packet(packet):
    """Callback function to analyze captured packets."""
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol_num = packet[IP].proto
        
        # Map protocol numbers to names
        protocol = "TCP" if protocol_num == 6 else "UDP" if protocol_num == 17 else "Other"

        print(f"[+] Source IP: {ip_src} --> Destination IP: {ip_dst} | Protocol: {protocol}")

        # Extract and display payload if present
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            # Truncate payload for readability and decode ignoring errors
            print(f"    Payload (Snippet): {payload[:50].decode('utf-8', errors='ignore')}...\n")
        else:
            print("    Payload: None\n")

if __name__ == "__main__":
    print("Starting Network Sniffer... (Capturing 10 packets)")
    print("-" * 60)
    # Sniff 10 packets to demonstrate functionality. Remove 'count=10' to run indefinitely.
    sniff(prn=analyze_packet, store=False, count=10)