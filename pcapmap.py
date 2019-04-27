#!/usr/bin/env python3

from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff
from twisted.names import client
from twisted.internet import defer, reactor, task
import argparse, socket, time, threading, sys

ip_src = ''
ip_dest = ''
tcp_sport = 0
tcp_dport = 0
num_packets_parsed = 0
start = time.time()

def parse_packet(packet):
    global num_packets_parsed

    if TCP in packet:
        host_list.add_host(packet[IP].src)
        host_list.add_host(packet[IP].dst)
        host_list.add_tcp_port(packet[IP].src, packet[TCP].sport, Host.PORT_SRC)
        host_list.add_tcp_port(packet[IP].dst, packet[TCP].dport, Host.PORT_DST)
    elif UDP in packet:
        host_list.add_host(packet[IP].src)
        host_list.add_host(packet[IP].dst)
        host_list.add_udp_port(packet[IP].src, packet[UDP].sport, Host.PORT_SRC)
        host_list.add_udp_port(packet[IP].dst, packet[UDP].dport, Host.PORT_DST)

    num_packets_parsed += 1



class Host:

    STATUS_UNK = 0
    STATUS_UP = 1

    STATUS_STRINGS = ["UNKNOWN", "UP"]

    PORT_SRC = 0
    PORT_DST = 1



    def __init__(self, ip_addr=''):
        self.ip_addr = ip_addr
        self.tcp_port_set = set()
        self.udp_port_set = set()
        self.hostname = "Unknown"
        self.status = Host.STATUS_UNK

    def resolve_name(self):
        #try:
        #    self.hostname = socket.gethostbyaddr(self.ip_addr)[0]
        #except socket.herror:
        #    self.hostname = "Unknown"
        self.d = client.lookupPointer(name=self.reverse_name_for_ip_address())
        self.d.addCallback(self.lookup_ptr_callback)
        return self.d


#        if answers:
#            self.hostname = answers[0]

    def lookup_ptr_callback(self, result):
        answers, authority, additional = result
        if answers:
            return answers

    def dns_success(self, result):
        self.hostname = result[0]
        for res in result:
            print(res)

    def dns_error(selfs, failure):
        import sys
        sys.stderr.write(str(failure))

    def reverse_name_for_ip_address(self):
        return '.'.join(reversed(self.ip_addr.split('.'))) + '.in-addr.arpa'

    def __lt__(self, other):
        return self.ip_addr < other.ip_addr

    def __eq__(self, other):
        return self.ip_addr == other.ip_addr

    def __gt__(self, other):
        return self.ip_addr > other.ip_addr

    def __str__(self):
        return self.ip_addr

    def __hash__(self):
        return hash(self.ip_addr)

    def add_tcp_port(self, tcp_port, port_direction):
        if tcp_port not in self.tcp_port_set:
            self.tcp_port_set.add(tcp_port)
        if port_direction == Host.PORT_SRC:
            self.status = Host.STATUS_UP


    def add_udp_port(self, udp_port, port_direction):
        if udp_port not in self.udp_port_set:
            self.udp_port_set.add(udp_port)
        if port_direction == Host.PORT_SRC:
            self.status = Host.STATUS_UP

    def print(self, include_hostnames=False):
        print("Ip Addr: %s" % self.ip_addr, end='')
        if include_hostnames == True:
            print("    Hostname: %s" % self.hostname, end='')
        print("    Status: %s" % Host.STATUS_STRINGS[self.status])
        for tport in sorted(self.tcp_port_set):
            print ("    %i/tcp" % tport)
        for uport in sorted(self.udp_port_set):
            print ("    %i/udp" % uport)



class HostList():

    def __init__(self, host_set=set(), dns_resolve=False):
        self.host_set = host_set
        self.dns_resolve = dns_resolve


    def add_host(self, ip_addr):
        global num_packets_parsed
        host = Host(ip_addr)
        if host not in self.host_set:
            print("\r", end='')
            print("[+][%i] New Host Found!  IP Addr: %s  " %(num_packets_parsed, ip_addr), end='')
            #thread = threading.Thread(target = host.resolve_name())
            #thread.start()
            d = host.resolve_name()
            d.addCallback(host.dns_success)
            d.addErrback(host.dns_error)
            self.host_set.add(host)

    def add_tcp_port(self, ip_addr, port, port_direction):
        temp_host = Host(ip_addr)
        for host in self.host_set:
            if host == temp_host:
                host.add_tcp_port(port, port_direction)

    def add_udp_port(self, ip_addr, port, port_direction):
        temp_host = Host(ip_addr)
        for host in self.host_set:
            if host == temp_host:
                host.add_udp_port(port, port_direction)

    def print(self):
        for host in sorted(self.host_set):
            host.print(self.dns_resolve)


parser = argparse.ArgumentParser(description='Parse pcap file for hosts, protocols, and ports')
parser.add_argument('pcap_file', nargs=1)
parser.add_argument('-n', '--no-dns-resolve', required=False, action='store_true', help="Do not resolve hostnames from IP Addresses (default: resolve hostnames)")
args = parser.parse_args()

pcap_file = args.pcap_file
host_list = HostList(set(), not args.no_dns_resolve)

packets = sniff(offline=pcap_file, prn=parse_packet, store=0)

reactor.callLater(60, reactor.stop); reactor.run()

host_list.print()
end = time.time()
hours, rem = divmod(end-start, 3600)
minutes, seconds = divmod(rem, 60)
print("\nElapsed Execution Time: {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))

