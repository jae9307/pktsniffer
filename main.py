from scapy.all import *

def read_udp_layer():
    encapsulated_layer = packet.getlayer("UDP")

    if encapsulated_layer is not None:
        print("UDP LAYER")
        print(f"SRC Port: {encapsulated_layer.sport}")
        print(f"Checksum: {encapsulated_layer.chksum}")

def read_tcp_layer():
    encapsulated_layer = packet.getlayer("TCP")
    if encapsulated_layer is not None:
        print("TCP LAYER")
        print(f"Flags: {encapsulated_layer.flags}")
        print(f"Window: {encapsulated_layer.window}")
        print(f"Acknowledgement Number: {encapsulated_layer.ack}")
    else:
        read_udp_layer()

def read_ethernet_layer():
    ethernet_layer = packet.getlayer("Ether")

    print("ETHERNET HEADER")
    print(f"MAC DST: {ethernet_layer.dst}")
    print(f"MAC SRC: {ethernet_layer.src}")
    print(f"Ethertype: {ethernet_layer.type}")

def read_ip_layer():
    ip_version = 4
    ip_layer = packet.getlayer("IP")
    if ip_layer is None:
        ip_layer = packet.getlayer("IPv6")
        ip_version = 6

    if ip_layer is not None:
        print(f"Packet Size: {ip_layer.len}")

        print("IP HEADER")
        print(f"Version: {ip_layer.version}")
        print(f"Total Length: {ip_layer.len}")
        print(f"Header Checksum: {ip_layer.chksum}")
        print(f"IP SRC: {ip_layer.src}")
        print(f"IP DST: {ip_layer.dst}")

        if ip_version == 4:
            print(f"Header Length: {ip_layer.ihl}")
            print(f"Type of Service: {ip_layer.tos}")
            print(f"Identification: {ip_layer.id}")
            print(f"Flags: {ip_layer.flags}")
            print(f"Fragment Offset: {ip_layer.frag}")
            print(f"Time to Live: {ip_layer.ttl}")
            print(f"Protocol: {ip_layer.proto}")

def filtering(args, packet):
    ip_layer = packet.getlayer("IP")
    if ip_layer is None:
        ip_layer = packet.getlayer("IPv6")

    if ip_layer is not None:
        if args.host is not None and ip_layer.src != args.host and ip_layer.dst != args.host:
            return False
    elif args.ip is True:
            return False

    tcp_layer = packet.getlayer("TCP")
    if tcp_layer is not None:
        if args.port is not None and tcp_layer.sport != args.port and tcp_layer.dport != args.port:
            return False
    elif args.tcp is True:
        return False

    udp_layer = packet.getlayer("UDP")
    if udp_layer is None and args.udp is True:
        return False

    icmp_layer = packet.getlayer("ICMP")
    if icmp_layer is None and args.icmp is True:
        return False

    return True

parser = argparse.ArgumentParser(prog='pktsniffer', description='Reads packet headers')
parser.add_argument('filename')
parser.add_argument('-host', action='store')
parser.add_argument('-port', action='store')
parser.add_argument('-ip', action='store_true')
parser.add_argument('-tcp', action='store_true')
parser.add_argument('-udp', action='store_true')
parser.add_argument('-icmp', action='store_true')
parser.add_argument('-net', action='store')
parser.add_argument('-c', action='store')

args = parser.parse_args()

packets = rdpcap(args.filename)

index = 1
for packet in packets:
    if filtering(args, packet):
        print(f"---------    Packet {index}    ---------")

        read_ethernet_layer()
        read_ip_layer()
        read_tcp_layer()

        index += 1