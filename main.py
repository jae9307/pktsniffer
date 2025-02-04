from scapy.all import *

a = rdpcap("test.pcap")

index = 1
for packet in a:
    ip_version = 4

    ethernet_layer = packet.getlayer("Ether")
    ip_layer = packet.getlayer("IP")
    if ip_layer is None:
        ip_layer = packet.getlayer("IPv6")
        ip_version = 6

    print(f"---------    Packet {index}    ---------")
    print("ETHERNET HEADER")
    print(f"MAC DST: {ethernet_layer.dst}")
    print(f"MAC SRC: {ethernet_layer.src}")
    print(f"Ethertype: {ethernet_layer.type}")

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

    index += 1