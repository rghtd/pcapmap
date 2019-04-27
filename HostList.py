import bisect
from Host import Host

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
