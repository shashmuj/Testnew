from scapy.all import sniff, send, Packet, BitField, ShortField, ByteField, IPField, IP, XShortField

# Define a custom header class
class MyCustomHeader(Packet):
    name = "MyCustomHeader"
    fields_desc = [
        BitField("version", 4, 4),                  
        BitField("header_length", 5, 4),            
        ShortField("total_length", 40),             
        ShortField("identification", 1234),         
        BitField("flags", 0, 3),                    
        BitField("fragment_offset", 0, 13),         
        ByteField("ttl", 64),                       
        ByteField("protocol", 143),                 
        XShortField("checksum", 0),                 
        IPField("src", "192.168.89.128"),           
        IPField("dst", "192.168.163.1")             
    ]

# Function to handle incoming packets
def handle_packet(packet):
    if MyCustomHeader in packet:
        custom_header = packet[MyCustomHeader]
        print(f"Received packet: {custom_header.summary()}")

        # Create a response packet
        response_header = MyCustomHeader(
            src=custom_header.dst,  # Swap src and dst for the response
            dst=custom_header.src,
            protocol=custom_header.protocol
        )
        response_ip = IP(src=custom_header.dst, dst=custom_header.src)
        response_packet = response_ip / response_header

        # Send the response packet
        send(response_packet)
        print(f"Sent response packet: {response_packet.summary()}")

# Function to start sniffing
def start_sniffing(interface="eth0"):
    sniff(iface=interface, filter="ip", prn=handle_packet)

if __name__ == "__main__":
    # Ensure you have the correct network interface
    interface = "eth0"  # Replace with the correct interface name if needed
    start_sniffing(interface)
