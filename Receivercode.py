from scapy.all import *

def packet_sniff_filter(packet):
    if IP in packet and packet[IP].proto == 6:  # Only TCP packets
        return True
    return False

def respond_to_packet(packet):
    # Print received packet header
    print("Received packet:")
    packet.show()
    
    # Create a response packet
    ip = IP(dst=packet[IP].src, src=packet[IP].dst)
    tcp = TCP(
        sport=packet[TCP].dport,
        dport=packet[TCP].sport,
        seq=packet[TCP].ack,
        ack=packet[TCP].seq + 1,
        flags="A",
        window=8192,
        chksum=0
    )
    
    response = ip/tcp
    
    # Calculate checksums
    response[IP].chksum = None
    response[TCP].chksum = None

    # Send response packet
    send(response, iface=conf.iface)
    print("Response sent.")

def main():
    print("Sniffing for packets...")
    sniff(filter="tcp", prn=respond_to_packet)

if __name__ == "__main__":
    main()
