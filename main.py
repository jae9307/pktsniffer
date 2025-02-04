from scapy.all import *

def udp():
    encapsulated_layer = packet.getlayer("UDP")

    if encapsulated_layer is not None:
        print("UDP LAYER")
        print(f"SRC Port: {encapsulated_layer.sport}")
        print(f"Checksum: {encapsulated_layer.chksum}")

def tcp():
    encapsulated_layer = packet.getlayer("TCP")
    if encapsulated_layer is not None:
        print("TCP LAYER")
        print(f"Flags: {encapsulated_layer.flags}")
        print(f"Window: {encapsulated_layer.window}")
        print(f"Acknowledgement Number: {encapsulated_layer.ack}")
    else:
        udp()

def ethernet():
    ethernet_layer = packet.getlayer("Ether")

    print("ETHERNET HEADER")
    print(f"MAC DST: {ethernet_layer.dst}")
    print(f"MAC SRC: {ethernet_layer.src}")
    print(f"Ethertype: {ethernet_layer.type}")

def ip():
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

a = rdpcap("test.pcap")

index = 1
for packet in a:
    print(f"---------    Packet {index}    ---------")

    ethernet()
    ip()
    tcp()

    index += 1