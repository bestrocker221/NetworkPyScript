# **DNS Server**

## Multi-threaded DNS Server

*dns_server_mt.py* is a multi-threaded process based DNS server which serves UDP and TCP requests at the same time. Both UDP and TCP servers run on their own process and for each new DNS query a new thread is launched. 

*It is not async structured and not reliable for high performance, it could just keep up some requests per second.*

dns_server_mt.py was done first in order to get hands on DNS query requests and response.


##Async DNS Server
*dns_server_async.py* aims to be a high level asynchronous dns server. 