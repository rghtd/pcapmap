#!/usr/bin/env python3

from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff

import argparse
from HostList import HostList

ip_src = ''
ip_dest = ''
tcp_sport = 0
tcp_dport = 0



def parse_packet(packet):
    if IP in packet:
        host_list.add_host(packet[IP].src)
        host_list.add_host(packet[IP].dst)
        if TCP in packet:
            host_list.add_tcp_port(packet[IP].src, packet[TCP].sport)
            host_list.add_tcp_port(packet[IP].dst, packet[TCP].dport)
        if UDP in packet:
            host_list.add_udp_port(packet[IP].src, packet[UDP].sport)
            host_list.add_udp_port(packet[IP].dst, packet[UDP].dport)




parser = argparse.ArgumentParser(description='Parse pcap file for hosts, protocols, and ports')
parser.add_argument('pcap_file', nargs=1)
parser.add_argument('-n', '--no-dns-resolve', required=False, action='store_true', help="Do not resolve hostnames from IP Addresses (default: resolve hostnames)")
args = parser.parse_args()

pcap_file = args.pcap_file

host_list = HostList([], args.no_dns_resolve)

packets = sniff(offline=pcap_file, prn=parse_packet, store=0)
#packets = rdpcap(pcap_file)
#for packet in packets:
#    parse_packet(packet)

host_list.print()



