from scapy.all import *

a = rdpcap("test.pcap")

for packet in a:
    ethernet_layer = packet.getlayer("Ether")
    ip_layer = packet.getlayer("IP")


    print(f"ETHERNET HEADER")
    print(f"Packet Size: {ip_layer.len}")
    print(f"MAC DST: {ethernet_layer.dst}")
    print(f"MAC SRC: {ethernet_layer.src}")
    print(f"Ethertype: {ethernet_layer.type}")

    print(f"IP HEADER")
    print(f"Version: {ip_layer.version}")
    print(f"Header Length: {ip_layer.ihl}")
    print(f"Type of Service: {ip_layer.tos}")
    print(f"Total Length: {ip_layer.len}")
    print(f"Identification: {ip_layer.id}")
    print(f"Flags: {ip_layer.flags}")
    print(f"Fragment Offset: {ip_layer.frag}")
    print(f"Time to Live: {ip_layer.ttl}")
    print(f"Protocol: {ip_layer.proto}")
    print(f"Header Checksum: {ip_layer.chksum}")
    print(f"IP SRC: {ip_layer.src}")
    print(f"IP SRC: {ip_layer.src}")
    print(f"IP DST: {ip_layer.dst}")