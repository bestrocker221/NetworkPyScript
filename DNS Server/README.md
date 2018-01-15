# **DNS Server**

*NB: I'm writing this in my free time, just to try, learn and improve.*

## Multi-threaded DNS Server

*dns_server_mt.py* is a multi-threaded process based DNS server which serves UDP and TCP requests at the same time. Both UDP and TCP servers run on their own process and for each new DNS query a new thread is launched. 

*It is not async structured and not reliable for high performance, it could just keep up some requests per second.*

dns_server_mt.py was done first in order to get hands on DNS query requests and response.

NOTE: may not work properly for too many requests.

## Async DNS Server

*dns_server_async.py* aims to be a high level asynchronous dns server. 
It is based on three thread:
* receiver thread
* server forwarder thread
* client forwarder thread

and make use of Queue for passing/sharing requests/responses among threads.

No other libraries used than Scapy.

*Performance:* (evaluated with [dnsblast](https://github.com/jedisct1/dnsblast))
* average 10 per second (Uncached)
* average 21 per second (Cached)

still very bad.


### **Installation**
**pip - download latest release from the python package index**

Use pip2 for python2 packages.
```bash
$ pip2 install -r requirements.txt
```

which include just [Scapy](https://github.com/secdev/scapy) framework

### **Use**

Just run the python2 script (with admin privileges)
```bash
$ sudo python2 dns_server_mt.py
```
