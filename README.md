# pcapmap
**pcapmap** utilizes Scapy to quickly parse pcap files for active hosts and ports actively being used. 

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

### Example:
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
Status at Capture Time: UP
Ports:
    20199/udp

--------------------------

Ip Addr: 65.165.167.86
Current Hostname: 65-165-167-86.volcano.net
Status at Capture Time: UNKNOWN
Ports:
    1434/udp

--------------------------
```


### Dependencies:
* python3
* scapy
* twisted
