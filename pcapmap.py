#!/usr/bin/env python3

from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff
from twisted.names import client
from twisted.internet import reactor
import argparse, time

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

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
        flags = packet[TCP].flags
        if flags & SYN and flags & ACK:
            host_list.add_synack_port(packet[IP].src, packet[TCP].sport)


    elif UDP in packet:
        host_list.add_host(packet[IP].src)
        host_list.add_host(packet[IP].dst)
        host_list.add_udp_port(packet[IP].src, packet[UDP].sport, Host.PORT_SRC)
        host_list.add_udp_port(packet[IP].dst, packet[UDP].dport, Host.PORT_DST)
    elif IP in packet:
        host_list.add_host(packet[IP].src)
        host_list.add_host(packet[IP].dst)

    num_packets_parsed += 1



class Host:

    STATUS_UNK = 0
    STATUS_UP = 1

    STATUS_STRINGS = ["UNKNOWN (No packets observed originating from host)", "UP (Packets observed originating from host)"]

    PORT_SRC = 0
    PORT_DST = 1



    def __init__(self, ip_addr=''):
        self.ip_addr = ip_addr
        self.tcp_port_set = set()
        self.synack_port_set = set()
        self.udp_port_set = set()
        self.hostname = "Unknown"
        self.status = Host.STATUS_UNK
        self.packet_count = -1

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
        global num_packets_parsed
        recordHeader = result[0]
        name_str_list = str(recordHeader.payload).split(' ')
        for name_str in name_str_list:
            if "name=" in name_str:
                self.hostname = name_str.split('=')[1]
                print("[+] Reverse Name Resolution Complete!  IP Addr: %s  Hostname: %s" % (self.ip_addr, self.hostname))

    def dns_error(self, failure):
        import sys
        sys.stderr.write("[-] Reverse Name Resolution Failed!  IP Addr: %s\n" % self.ip_addr)

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

    def add_synack_port(self, synack_port):
        if synack_port not in self.synack_port_set:
            self.synack_port_set.add(synack_port)

    def add_udp_port(self, udp_port, port_direction):
        if udp_port not in self.udp_port_set:
            self.udp_port_set.add(udp_port)
        if port_direction == Host.PORT_SRC:
            self.status = Host.STATUS_UP

    def print(self, include_hostnames=False):
        print("Ip Addr: %s" % self.ip_addr)
        if include_hostnames == True:
            print("Current Hostname: %s" % self.hostname)
        print("Status at Capture Time: %s" % Host.STATUS_STRINGS[self.status])
        print("Ports: ")
        for tport in sorted(self.tcp_port_set):
            print ("    %i/tcp" % tport, end='')
            if tport in self.synack_port_set:
                print("    LISTENING (SYNACK verified)", end='')
            print("")
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
            print("[+][%i] New Host Found!  IP Addr: %s  " %(num_packets_parsed, ip_addr))
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

    def add_synack_port(self, ip_addr, port):
        temp_host = Host(ip_addr)
        for host in self.host_set:
            if host == temp_host:
                host.add_synack_port(port)

    def add_udp_port(self, ip_addr, port, port_direction):
        temp_host = Host(ip_addr)
        for host in self.host_set:
            if host == temp_host:
                host.add_udp_port(port, port_direction)

    def print(self):
        print("\n*******************\n* PCAPMAP Results *\n*******************")
        for host in sorted(self.host_set):
            print("\n--------------------------\n")
            host.print(self.dns_resolve)
        print("\n--------------------------")


parser = argparse.ArgumentParser(description='Parse pcap file for hosts, protocols, and ports')
parser.add_argument('pcap_file', nargs=1)
parser.add_argument('-n', '--no-dns-resolve', required=False, action='store_true', help="Do not resolve hostnames from IP Addresses (default: resolve hostnames)")
parser.add_argument('-t', '--timeout', required=False, default=20, help="Timeout in seconds (default: 20)")
args = parser.parse_args()

pcap_file = args.pcap_file
host_list = HostList(set(), not args.no_dns_resolve)

packets = sniff(offline=pcap_file, prn=parse_packet, store=0)

if args.no_dns_resolve == False:
    reactor.callLater(10, reactor.stop); reactor.run()

host_list.print()
end = time.time()
hours, rem = divmod(end-start, 3600)
minutes, seconds = divmod(rem, args.timeout)
print("\nElapsed Execution Time: {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))

