# pcapmap
**pcapmap** utilizes Scapy to quickly parse pcap files for active hosts and ports actively being used. 

#### Usage:
```
python3 pcapmap.py [-h] [-n] pcap_file

Parse pcap file for hosts and ports

positional arguments:
  pcap_file

optional arguments:
  -h, --help            show this help message and exit
  -n, --no-dns-resolve  Do not resolve hostnames from IP Addresses (default:
                        resolve hostnames)
```

#### Dependencies:
* python3
* scapy

