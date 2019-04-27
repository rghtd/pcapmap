import bisect
import socket

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

