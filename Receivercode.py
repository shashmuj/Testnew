from scapy.all import sniff, hexdump, IP

# Function to handle incoming packets
def handle_packet(packet):
    # Print a simple summary of the packet
    print(packet.summary())
    
    # Print detailed packet information
    print(packet.show())
    
    # Print raw packet data in hex
    hexdump(packet)
    
    print("\n" + "="*80 + "\n")

# Function to start sniffing
def start_sniffing(interface="eno1"):
    print(f"Starting packet sniffing on interface: {interface}")
    sniff(iface=interface, prn=handle_packet)

if __name__ == "__main__":
    # Ensure you have the correct network interface
    interface = "eno1"  # Replace with the correct interface name if needed
    start_sniffing(interface)
