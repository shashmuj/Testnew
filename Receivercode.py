from scapy.all import *
import argparse

# Define a simple custom protocol class
class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
        ByteField("version", 4),
        ByteField("ihl", 5),
        ByteField("tos", 0),
        ShortField("length", 0),
        ShortField("id", 1),
        ShortField("frag_off", 0),
        ByteField("ttl", 64),
        ByteField("proto", 253),
        XShortField("checksum", None),
        IPField("src", "0.0.0.0"),
        IPField("dst", "0.0.0.0"),
        ShortField("sport", 12345),
        ShortField("dport", 80),
        IntField("seq", 0),
        IntField("ack", 0),
        ByteField("dataofs", 5),
        ByteField("reserved", 0),
        FlagsField("flags", 0, 8, ["F", "S", "R", "P", "A", "U", "E", "C"]),
        ShortField("window", 8192),
        XShortField("tcp_chksum", None),
        ShortField("urgptr", 0)
    ]

def packet_callback(packet):
    # Print general packet information
    print("Received packet:")
    packet.show()

    # Prepare and send a response packet
    response_pkt = CustomProtocol(
        version=4,
        ihl=5,
        tos=0,
        length=40,  # Example length
        id=1,
        frag_off=0,
        ttl=64,
        proto=253,
        src="0.0.0.0",  # Set appropriate values
        dst=packet[IP].src if IP in packet else "0.0.0.0",
        sport=80,  # Example port
        dport=12345,
        seq=0,
        ack=0,
        dataofs=5,
        flags=0x10,  # ACK flag
        window=8192,
        urgptr=0
    )

    # Send the response packet
    ip_response_pkt = IP(src=response_pkt.src, dst=response_pkt.dst, proto=response_pkt.proto) / response_pkt
    send(ip_response_pkt)
    print("Response sent:")
    response_pkt.show()

def main():
    parser = argparse.ArgumentParser(description="Receive and respond to custom protocol packets.")
    parser.add_argument("sender_ip", help="IP address of the sender to filter")
    parser.add_argument("iface", help="Network interface to use")
    args = parser.parse_args()

    # Create a filter to capture packets only from the specified sender IP
    filter_str = f"src host {args.sender_ip}"

    # Sniff packets on the specified interface with the filter
    sniff(iface=args.iface, prn=packet_callback, filter=filter_str, store=0)

if __name__ == "__main__":
    main()
