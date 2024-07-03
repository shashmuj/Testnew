from scapy.all import sniff, send, Packet, BitField, ShortField, ByteField, IPField, IP, XShortField, checksum, hexdump
import struct

# Define a custom header class for the receiver
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
        ShortField("seq_num", 0),                  
        IPField("src", "128.110.217.142"),           
        IPField("dst", "128.110.217.34")             
    ]

# Function to calculate checksum
def calculate_checksum(packet):
    return checksum(bytes(packet))

# Function to handle incoming packets
def handle_packet(packet):
    if MyCustomHeader in packet:
        custom_header = packet[MyCustomHeader]
        print(f"Received packet: {custom_header.summary()}")

        # Validate checksum
        original_checksum = custom_header.checksum
        custom_header.checksum = 0
        calculated_checksum = calculate_checksum(custom_header)
        if original_checksum == calculated_checksum:
            print("Checksum is valid.")
        else:
            print(f"Checksum is invalid. Original: {original_checksum}, Calculated: {calculated_checksum}")

        # Print detailed packet information
        packet.show()
        hexdump(packet)

        # Create an acknowledgment packet
        ack_header = MyCustomHeader(
            src=custom_header.dst,  # Swap src and dst for the response
            dst=custom_header.src,
            protocol=custom_header.protocol,
            seq_num=custom_header.seq_num + 1  # Increment sequence number
        )
        ack_ip = IP(src=custom_header.dst, dst=custom_header.src)
        ack_packet = ack_ip / ack_header

        # Send the acknowledgment packet
        send(ack_packet)
        print(f"Sent acknowledgment packet: {ack_packet.summary()}\n" + "="*80 + "\n")

# Function to start sniffing
def start_sniffing(interface="eno1"):
    print(f"Starting packet sniffing on interface: {interface}")
    sniff(iface=interface, filter="ip", prn=handle_packet)

if __name__ == "__main__":
    # Ensure you have the correct network interface
    interface = "eno1"  # Replace with the correct interface name if needed
    start_sniffing(interface)
