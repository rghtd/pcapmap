# pcapmap
**pcapmap** utilizes Scapy to quickly parse pcap files for active hosts and ports actively being used. 

#### Usage:
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

#### Dependencies:
* python3
* scapy
* twisted
