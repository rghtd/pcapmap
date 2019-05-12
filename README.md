# pcapmap
**pcapmap** utilizes Scapy to quickly parse pcap files for active hosts and ports. 

### Usage:
```
python3 pcapmap.py [-h] [-n] [-t TIMEOUT] pcap_file

Parse pcap file for hosts, protocols, and ports

positional arguments:
  pcap_file

optional arguments:
  -h, --help            show this help message and exit
  -n, --no-dns-resolve  Do not resolve hostnames from IP Addresses (default:
                        resolve hostnames)
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout in seconds (default: 20)

```

### Dependencies:
* python3
* scapy
* twisted
```
pip3 install -r requirements.txt
```

### Examples:
##### HTTP Request Example
```
python3 pcapmap.py http.cap

[+][0] New Host Found!  IP Addr: 145.254.160.237
[+][0] New Host Found!  IP Addr: 65.208.228.223
[+][12] New Host Found!  IP Addr: 145.253.2.203
[+][17] New Host Found!  IP Addr: 216.239.59.99
[+] Reverse Name Resolution Complete!  IP Addr: 145.254.160.237  Hostname: dialin-145-254-160-237.pools.arcor-ip.net
[-] Reverse Name Resolution Failed!  IP Addr: 216.239.59.99
[-] Reverse Name Resolution Failed!  IP Addr: 145.253.2.203
[-] Reverse Name Resolution Failed!  IP Addr: 65.208.228.223

*******************
* PCAPMAP Results *
*******************

--------------------------

Ip Addr: 145.253.2.203
Current Hostname: Unknown
Status at Capture Time: UP (Packets observed originating from host)
Ports:
    53/udp

--------------------------

Ip Addr: 145.254.160.237
Current Hostname: dialin-145-254-160-237.pools.arcor-ip.net
Status at Capture Time: UP (Packets observed originating from host)
Ports:
    3371/tcp
    3372/tcp
    3009/udp

--------------------------

Ip Addr: 216.239.59.99
Current Hostname: Unknown
Status at Capture Time: UP (Packets observed originating from host)
Ports:
    80/tcp

--------------------------

Ip Addr: 65.208.228.223
Current Hostname: Unknown
Status at Capture Time: UP (Packets observed originating from host)
Ports:
    80/tcp    LISTENING (SYNACK verified)

--------------------------


```
##### Slammer Worm Example
```
python3 pcapmap.py slammer.pcap

[+][0] New Host Found!  IP Addr: 213.76.212.22
[+][0] New Host Found!  IP Addr: 65.165.167.86
[+] Reverse Name Resolution Complete!  IP Addr: 213.76.212.22  Hostname: 22.212.76.213.dynamic.jazztel.es
[+] Reverse Name Resolution Complete!  IP Addr: 65.165.167.86  Hostname: 65-165-167-86.volcano.net

*******************
* PCAPMAP Results *
*******************

--------------------------

Ip Addr: 213.76.212.22
Current Hostname: 22.212.76.213.dynamic.jazztel.es
Status at Capture Time: UP (Packets observed originating from host)
Ports:
    20199/udp

--------------------------

Ip Addr: 65.165.167.86
Current Hostname: 65-165-167-86.volcano.net
Status at Capture Time: UNKNOWN (No packets observed originating from host)
Ports:
    1434/udp

--------------------------

Elapsed Execution Time: 00:00:10.01


```


