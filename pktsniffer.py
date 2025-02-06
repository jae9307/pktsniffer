"""Read headers from packets in a capture file"""
from scapy.all import *


def read_udp_layer(packet):
    """
    read_udp_layer reads and prints fields from the UDP layer.

    read_udp_layer parses the UDP header of a packet if it is present, and
    prints its checksum and port fields.
    :param packet: the packet being parsed
    """
    encapsulated_layer = packet.getlayer("UDP")
    if encapsulated_layer is not None:
        print("UDP LAYER")
        print(f"SRC Port: {encapsulated_layer.sport}")
        print(f"DST Port: {encapsulated_layer.dport}")
        print(f"Checksum: {encapsulated_layer.chksum}")


def read_tcp_layer(packet):
    """
    read_tcp_layer reads and prints fields from the TCP layer.

    read_tcp_layer parses the TCP layer of a packet if it is present, and
    prints its Flags, Window, Acknowledgement Number and port fields. If a TCP
    layer isn't present in the packet, read_udp_layer is called.
    :param packet: the packet being parsed
    """
    encapsulated_layer = packet.getlayer("TCP")
    if encapsulated_layer is not None:
        print("TCP LAYER")
        print(f"Flags: {encapsulated_layer.flags}")
        print(f"Window: {encapsulated_layer.window}")
        print(f"Acknowledgement Number: {encapsulated_layer.ack}")
        print(f"SRC Port: {encapsulated_layer.sport}")
        print(f"DST Port: {encapsulated_layer.dport}")
    else:
        read_udp_layer(packet)


def read_ethernet_layer(packet):
    """
    read_ethernet_layer reads and prints fields from the Ethernet layer.

    read_ethernet_layer prints the MAC destination, MAC source, and Ethertype
    fields of the Ethernet header of a packet.
    :param packet: the packet being parsed
    """
    ethernet_layer = packet.getlayer("Ether")
    print("ETHERNET HEADER")
    print(f"MAC DST: {ethernet_layer.dst}")
    print(f"MAC SRC: {ethernet_layer.src}")
    print(f"Ethertype: {ethernet_layer.type}")


def read_ip_layer(packet):
    """
    read_ip_layer reads and prints fields from the IP layer.

    read_ip_layer prints various fields from the IP header of a packet. By
    default, it tries to read the header as an IPv4 header, which contains
    more fields than the IPv6 header. If the packet doesn't have an IPv4
    header, the function tries to read the IPv6 header of the packet.
    :param packet: the packet being parsed
    """
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
    """
    filtering discards packets according to user-selected parameters.

    filtering parses various headers of a packet, and crosschecks these
    headers against parameters selected by the user to determine whether to
    keep or discard the current packet.
    :param args: the parameters selected by the user
    :param packet: the packet under consideration
    :return: True if packet should be kept, False if it should be discarded
    """
    ip_layer = packet.getlayer("IP")
    if ip_layer is None:
        ip_layer = packet.getlayer("IPv6")

    # Discards the packet if its source and destination IP addresses don't
    # match the IP address specified by host parameter, or if the packet
    # doesn't have an IP header and either the ip parameter, the host
    # parameter, or the port parameter was selected.
    if ip_layer is not None:
        if (args.host is not None and ip_layer.src != args.host
                and ip_layer.dst != args.host):
            return False
        if (args.net is not None and ip_layer.src[:11] != args.net[:11]
                and ip_layer.dst[:11] != args.net[:11]):
            return False
    elif args.ip is True or args.host is not None or args.net is not None:
            return False

    # Discards the packet if its source and destination ports don't match the
    # port specified by the port parameter, or if the packet doesn't have a
    # TCP header and the tcp parameter was selected
    tcp_layer = packet.getlayer("TCP")
    if tcp_layer is not None:
        if (args.port is not None and tcp_layer.sport != int(args.port)
                and tcp_layer.dport != int(args.port)):
            return False
    elif args.tcp is True:
        return False

    # Discards the packet if its source and destination ports don't match the
    # port specified by the port parameter, or if the packet doesn't have a
    # UDP layer and the udp parameter was selected.
    udp_layer = packet.getlayer("UDP")
    if udp_layer is None and args.udp is True:
        return False
    elif (udp_layer is not None and args.port is not None
            and udp_layer.sport != int(args.port)
            and udp_layer.dport != int(args.port)):
        return False

    # Discards the packet if its source and destination ports don't match the
    # port specified by the port parameter
    sctp_layer = packet.getlayer("SCTP")
    if (sctp_layer is not None and sctp_layer.sport != int(args.port)
            and sctp_layer.dport != int(args.port)):
        return False

    # Discards the packet if it doesn't have a tcp, udp or sctp layer and the
    # port parameter was selected
    if (tcp_layer is None and udp_layer is None and sctp_layer is None
            and args.port is not None):
        return False

    # Discards the packet if it doesn't have an ICMP layer and the icmp
    # parameter was selected.
    icmp_layer = packet.getlayer("ICMP")
    if icmp_layer is None and args.icmp is True:
        return False

    return True


def main():
    """Parse command line arguments, filter and read packets in the file"""

    # Define command line parameters.
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

    # Store list of packets from the indicated file.
    packets = rdpcap(args.filename)

    # For each packet in the file, print fields from its headers if the packet
    # meets the criteria established by the command line parameters.
    index = 1
    packet_number = 1  # as displayed in wireshark
    for packet in packets:
        if args.c is not None and int(args.c) < index:
            break
        if filtering(args, packet):
            print(f"---------    Packet {packet_number}    ---------")

            read_ethernet_layer(packet)
            read_ip_layer(packet)
            read_tcp_layer(packet)

            index += 1

        packet_number += 1

if __name__ == '__main__':
    main()