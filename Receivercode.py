from scapy.all import sniff, IP, send, Raw, Packet
from scapy.fields import BitField, ShortField, ByteField, IPField, XShortField, checksum
import struct
import argparse

# Define the custom header class for the receiver
class MyCustomHeader(Packet):
    name = "MyCustomHeader"
    fields_desc = [
        BitField("version", 4, 4),                  
        BitField("header_length", 5, 4),            
        ShortField("total_length", 40),             
        ShortField("identification", 0),            
        BitField("flags", 0, 3),                    
        BitField("fragment_offset", 0, 13),         
        ByteField("ttl", 0),                        
        ByteField("protocol", 0),                   
        XShortField("checksum", 0),                 
        IPField("src", "0.0.0.0"),                  
        IPField("dst", "0.0.0.0")                   
    ]

    def post_build(self, p, pay):
        if self.checksum == 0:
            chksum = checksum(p)
            chksum_bytes = struct.pack('!H', chksum)
            p = p[:10] + chksum_bytes + p[12:]
        return p + pay

def handle_packet(packet, sender_ip):
    ip_header = packet.getlayer(IP)
    if ip_header and ip_header.src == sender_ip:
        print("=== Received Packet ===")
        packet.show()

        if MyCustomHeader in packet:
            custom_header = packet[MyCustomHeader]
            print("=== Custom Header ===")
            print(f"Version: {custom_header.version}")
            print(f"Header Length: {custom_header.header_length}")
            print(f"Total Length: {custom_header.total_length}")
            print(f"Identification: {custom_header.identification}")
            print(f"Flags: {custom_header.flags}")
            print(f"Fragment Offset: {custom_header.fragment_offset}")
            print(f"TTL: {custom_header.ttl}")
            print(f"Protocol: {custom_header.protocol}")
            print(f"Checksum: {hex(custom_header.checksum)}")
            print(f"Source IP: {custom_header.src}")
            print(f"Destination IP: {custom_header.dst}")
        else:
            print("Received a packet with no custom header.")

        # Prepare and send a response packet
        response = IP(src=ip_header.dst, dst=ip_header.src) / Raw(load="Packet received")
        print("=== Sending Response Packet ===")
        response.show()
        send(response)

        # Optionally, listen for the response packet here
        print("Listening for response from sender...")
        sniff(iface=args.iface, filter=f"ip src {ip_header.src}", count=1, prn=lambda p: handle_response(p, ip_header.src))
    else:
        print(f"Ignored packet from {ip_header.src} as it is not from the sender {sender_ip}")

def handle_response(packet, sender_ip):
    ip_header = packet.getlayer(IP)
    if ip_header and ip_header.src == sender_ip:
        print("=== Received Response Packet ===")
        packet.show()
        ip_header = packet.getlayer(IP)
        if ip_header:
            print("=== IP Header of Response ===")
            print(f"Source IP: {ip_header.src}")
            print(f"Destination IP: {ip_header.dst}")
            print(f"Protocol: {ip_header.proto}")
            print(f"Version: {ip_header.version}")
            print(f"IHL: {ip_header.ihl}")
            print(f"TOS: {ip_header.tos}")
            print(f"Total Length: {ip_header.len}")
            print(f"Identification: {ip_header.id}")
            print(f"Flags: {ip_header.flags}")
            print(f"Fragment Offset: {ip_header.frag}")
            print(f"TTL: {ip_header.ttl}")
            print(f"Checksum: {hex(ip_header.chksum)}")
            print(f"Options: {ip_header.options}")

def main():
    parser = argparse.ArgumentParser(description="Receive and respond to custom IPv4 packets")
    parser.add_argument("--iface", required=True, help="Network interface to sniff on")
    parser.add_argument("--sender_ip", required=True, help="Sender IP address")

    args = parser.parse_args()

    # Construct the filter to only capture packets from the sender IP
    filter_str = f"ip src {args.sender_ip}"

    print("Starting packet sniffing...")
    sniff(iface=args.iface, filter=filter_str, prn=lambda packet: handle_packet(packet, args.sender_ip))

if __name__ == "__main__":
    main()
