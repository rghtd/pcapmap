#!/usr/bin/env python3

from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff
from twisted.names import client
from twisted.internet import reactor
import argparse, time, sys

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

def parse_packet(host_list):
    def parse_packet_int(packet):
        global num_packets_parsed
        src_host = None
        src_socket = None
        dst_host = None
        dst_socket = None
        socket_connection = None
        if IP in packet:
            src_host = host_list.add_or_find_host(Host(packet[IP].src), Host.PORT_SRC)
            src_host.status = Host.STATUS_UP
            dst_host = host_list.add_or_find_host(Host(packet[IP].dst), Host.PORT_DST)
            if TCP in packet:
                src_socket = Socket(src_host.ip_addr, packet[TCP].sport, Socket.TRANS_TCP, Socket.STATUS_UP)
                dst_socket = Socket(dst_host.ip_addr, packet[TCP].dport, Socket.TRANS_TCP, Socket.STATUS_UNK)
                src_socket = src_host.add_or_find_socket(src_socket)
                dst_socket = dst_host.add_or_find_socket(dst_socket)
                flags = packet[TCP].flags
                if flags & SYN and flags & ACK:
                    src_socket.stype = Socket.TYPE_SERVER
                elif flags & SYN and not flags & ACK:
                    src_socket.stype = Socket.TYPE_CLIENT

            elif UDP in packet:
                src_socket = Socket(src_host.ip_addr, packet[UDP].sport, Socket.TRANS_UDP, Socket.STATUS_UP)
                dst_socket = Socket(dst_host.ip_addr, packet[UDP].dport, Socket.TRANS_UDP, Socket.STATUS_UNK)
                src_socket = src_host.add_or_find_socket(src_socket)
                dst_socket = dst_host.add_or_find_socket(dst_socket)
            if TCP in packet or UDP in packet:
                socket_connection = SocketConnection(src_socket, dst_socket)
                src_socket.add_or_find_socket_connection(socket_connection)
                dst_socket.add_or_find_socket_connection(socket_connection)


        num_packets_parsed += 1
    return parse_packet_int

class SocketConnection:
    def __init__(self, socket1, socket2):
        self.socket_set = set()
        self.socket_set.add(socket1)
        self.socket_set.add(socket2)
        self.socket1 = socket1
        self.socket2 = socket2

    def __hash__(self):
        hashstr = ""
        for socket in sorted(self.socket_set):
            hashstr += socket.ip_addr
            hashstr += str(socket.port)
        return hash(hashstr)


class Socket:

    TRANS_UDP = 0
    TRANS_TCP = 1

    TRANS_STRINGS = [ "udp" , "tcp" ]

    TYPE_UNK = 0
    TYPE_CLIENT = 1
    TYPE_SERVER = 2

    STATUS_UNK = 0
    STATUS_UP = 1


    def __init__(self, ip_addr, port, trans, status=STATUS_UNK, stype=TYPE_UNK):
        self.ip_addr = ip_addr
        self.port = port
        self.trans = trans
        self.status = status
        self.socket_connection_set = set()
        self.stype = stype

    def __hash__(self):
        return hash(str(self.port) + self.ip_addr)

    def __lt__(self, other):
        return self.ip_addr + str(self.port) < self.ip_addr + str(other.port)

    def __eq__(self, other):
        return self.ip_addr + str(self.port) == self.ip_addr + str(other.port)

    def __gt__(self, other):
        return self.ip_addr + str(self.port) > self.ip_addr + str(other.port)


    def add_or_find_socket_connection(self, socket_connection):
        identifying_socket = None
        if socket_connection.socket1 == self:
            identifying_socket = socket_connection.socket2
        else:
            identifying_socket  = socket_connection.socket1
        for socket_conn in self.socket_connection_set:
            if identifying_socket in socket_conn.socket_set:
                return socket_conn
        
        self.socket_connection_set.add(socket_connection)
        return socket_connection

    def get_string_trans(self):
        return Socket.TRANS_STRINGS[self.trans]

    def set_type(self, stype):
        self.stype = stype



class Host:

    STATUS_UNK = 0
    STATUS_UP = 1

    STATUS_STRINGS = ["UNKNOWN (No packets observed originating from host)", "UP (Packets observed originating from host)"]

    PORT_SRC = 0
    PORT_DST = 1
    HOST_SRC = 2
    HOST_DST = 3



    def __init__(self, ip_addr=''):
        self.ip_addr = ip_addr
        self.tcp_port_set = set()
        self.synack_port_set = set()
        self.udp_port_set = set()
        self.hostname = "Unknown"
        self.status = Host.STATUS_UNK
        self.packet_count = -1
        self.socket_set = set()

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

    def add_or_find_socket(self, socket):
        if socket not in self.socket_set:
            self.socket_set.add(socket)
            return socket
        else:
            for ret_socket in self.socket_set:
                if ret_socket == socket:
                    return ret_socket


    def print_new(self, include_hostnames=False):
        print("Ip Addr: %s" % self.ip_addr)
        if include_hostnames == True:
            print("Current Hostname: %s" % self.hostname)
        print("Status at Capture Time: %s" % Host.STATUS_STRINGS[self.status])
        print("Ports: ")
        for socket in sorted(self.socket_set):
            print("    %i/%s" % (socket.port, socket.get_string_trans()), end='')
            if socket.stype == Socket.TYPE_SERVER:
                print("  <--  LISTENING (SYNACK observed)")
            elif socket.stype == Socket.TYPE_CLIENT:
                print("  +--  CLIENT (SYN observed)")
            elif socket.stype == Socket.TYPE_UNK:
                print("  ---  UNK")
            last_print_sock = None
            sock_counter = 0
            num_socks = len(socket.socket_connection_set)
            for sock_conn in socket.socket_connection_set:
                print_sock = None
                if sock_conn.socket1 == socket:
                   print_sock = sock_conn.socket2
                else:
                    print_sock = sock_conn.socket1
                if sock_counter == 0:
                    if socket.stype == Socket.TYPE_SERVER:
                        print("                --+  %s :%i" %(print_sock.ip_addr, print_sock.port), end='')
                    elif socket.stype == Socket.TYPE_CLIENT:
                        print("                -->  %s :%i" %(print_sock.ip_addr, print_sock.port), end='')
                    elif socket.stype == Socket.TYPE_UNK:
                        print("                ---  %s :%i" %(print_sock.ip_addr, print_sock.port), end='')
                else:
                    print(" :%i" % print_sock.port, end='')
                last_print_sock = print_sock
                sock_counter += 1
                if num_socks == sock_counter:
                    print("")
            print("")


class HostList():

    def __init__(self, host_set=set(), dns_resolve=False):
        self.host_set = host_set
        self.dns_resolve = dns_resolve


    def add_or_find_host(self, host, direction):
        global num_packets_parsed
        if host not in self.host_set:
            print("[+][%i] New Host Found!  IP Addr: %s  " %(num_packets_parsed, host.ip_addr))
            if self.dns_resolve == True:
                d = host.resolve_name()
                d.addCallback(host.dns_success)
                d.addErrback(host.dns_error)
            if direction == Host.HOST_SRC:
                host.status = Host.STATUS_UP
            self.host_set.add(host)
            return host
        else:
            for ret_host in self.host_set:
                if ret_host == host:
                    return ret_host

    def print(self):
        print("\n*******************\n* PCAPMAP Results *\n*******************")
        for host in sorted(self.host_set):
            print("\n--------------------------\n")
            host.print_new(self.dns_resolve)
        print("\n--------------------------")

def main(argv):
    start = time.time()
    parser = argparse.ArgumentParser(description='Parse pcap file for hosts, protocols, and ports')
    parser.add_argument('pcap_file', nargs=1)
    parser.add_argument('-n', '--no-dns-resolve', required=False, action='store_true', help="Do not resolve hostnames from IP Addresses (default: resolve hostnames)")
    parser.add_argument('-t', '--timeout', required=False, default=20, help="Timeout in seconds (default: 20)")
    args = parser.parse_args(argv)

    pcap_file = args.pcap_file
    host_list = HostList(set(), not args.no_dns_resolve)

    packets = sniff(offline=pcap_file, prn=parse_packet(host_list), store=0)

    if args.no_dns_resolve == False:
        reactor.callLater(10, reactor.stop); reactor.run()

    host_list.print()
    end = time.time()
    hours, rem = divmod(end-start, 3600)
    minutes, seconds = divmod(rem, args.timeout)
    print("\nElapsed Execution Time: {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))


if __name__ == "__main__":
    main(sys.argv[1:])
