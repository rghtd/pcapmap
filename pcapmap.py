#!/usr/bin/env python3

from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff

import argparse, bisect, socket

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


class Host:


    def __init__(self, ip_addr='', no_dns_resolve=False):
        self.ip_addr = ip_addr
        self.tcp_port_list = []
        self.udp_port_list = []
        self.no_dns_resolve = no_dns_resolve
        self.hostname = ""
        try:
            if not self.no_dns_resolve:
                self.hostname = socket.gethostbyaddr(self.ip_addr)[0]
        except socket.herror:
            self.hostname = "Unknown"

    def __lt__(self, other):
        return self.ip_addr < other.ip_addr

    def add_tcp_port(self, tcp_port):
        if tcp_port not in self.tcp_port_list:
            bisect.insort(self.tcp_port_list, tcp_port)


    def add_udp_port(self, udp_port):
        if udp_port not in self.udp_port_list:
            bisect.insort(self.udp_port_list, udp_port)

    def print(self):
        if not self.no_dns_resolve:
            print("Hostname: %s    " % self.hostname, end='')
        print("Ip Addr: %s" % self.ip_addr)
        for tport in self.tcp_port_list:
            print ("    %i/tcp" % tport)
        for uport in self.udp_port_list:
            print ("    %i/udp" % uport)


class HostList:

    def __init__(self, host_list=[], no_dns_resolve=False):
        self.host_list = host_list
        self.num = 0
        self.no_dns_resolve = no_dns_resolve

    def add_host(self, ip_addr):
        host_addrs = []
        if self.num != 0:
            host_addrs = set(host.ip_addr for host in self.host_list)
        if ip_addr not in host_addrs or self.num == 0:
            host = Host(ip_addr, self.no_dns_resolve)
            bisect.insort(self.host_list, host)
            self.num += 1

    def add_tcp_port(self, ip_addr, port):
        for host in self.host_list:
            if host.ip_addr == ip_addr:
                host.add_tcp_port(port)
                break

    def add_udp_port(self, ip_addr, port):
        for host in self.host_list:
            if host.ip_addr == ip_addr:
                host.add_udp_port(port)
                break

    def print(self):
        for host in self.host_list:
            host.print()


parser = argparse.ArgumentParser(description='Parse pcap file for hosts, protocols, and ports')
parser.add_argument('pcap_file', nargs=1)
parser.add_argument('-n', '--no-dns-resolve', required=False, action='store_true', help="Do not resolve hostnames from IP Addresses (default: resolve hostnames)")
args = parser.parse_args()

pcap_file = args.pcap_file

host_list = HostList([], args.no_dns_resolve)

packets = sniff(offline=pcap_file, prn=parse_packet, store=0)

host_list.print()
