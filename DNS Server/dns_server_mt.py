#! /usr/bin/python
from scapy.all import *
from threading import Thread
from multiprocessing import Process
import sys, datetime, signal, struct


DNS_SERVER = "8.8.8.8" 	#google dns
cache = {}	#in-memory caching

def search_cache(hostname):	
	if hostname in cache.keys():
		return cache[hostname]["raw"]

def dns_request(dns):
	resp = sr1(IP(dst=DNS_SERVER)/UDP(dport=53)/dns, timeout=3, verbose=False)
	if resp and resp.haslayer(DNS):
		dns = resp[DNS]
		return dns
	else:
		print("NO DNS RETURNED FOR " + dns.qd.qname)
		raise KeyError

def forward_client_query(ptype, data, addr):
	data = DNS(data)
	qname = data.qd.qname
	tid = data.id 		#DNS transaction id
	print(ptype +" [" + str(addr[0]) + ":" + str(addr[1]) +"]" + " REQUESTED: " + qname),
	dns = search_cache(qname)
	if dns:
		print("CACHE HIT")
	else:
		print("CACHE MISS")
		try:
			dns = dns_request(data) #DNS format
			cache.update({qname:{"raw":dns, "date":str(datetime.datetime.now())}}) #save full DNS response
		except KeyError:
			print("Discharding " + qname)
			return
	dns.id = tid 	#change DNS transaction id
	return dns


class UDPServerProcess(Process):
	def __init__(self):
		Process.__init__(self)
		self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.server.bind(('', 53))
		self.BUFFER_SIZE = 1024
		print("UDP DNS server started on port 53")
	
	def terminate(self):
		print("CLOSING UDP PROCESS")
		super(UDPServerProcess, self).terminate()

	def run(self):
		while True:
			try:
				th = Thread(target=self.handleUDPRequest, args=self.server.recvfrom(self.BUFFER_SIZE))
				th.start()
			except KeyboardInterrupt:
				return
			except Exception as e:
				print("{}".format(e))
				self.terminate()

	def handleUDPRequest(self, data, addr):
		if DNS_SERVER in addr[0]:
			return
		dns = forward_client_query("UDP", data, addr)
		self.UDPSend(dns, addr) 	#send back to client the final dns response

	def UDPSend(self, dns, addr):
		msg = Ether()/IP(dst=addr[0])/UDP(sport=53,dport=addr[1])/dns
		try:
			print("UDP [" + str(addr[0]) + ":" + str(addr[1]) +"]" + " ANSWER FOR " 
				+ str(dns.qd.qname) + " --> " + str(dns.an.rdata))
		except AttributeError:
			print("NONE TYPE ?? FOR " + dns.qd.qname)
			return
		try:
			sendp(msg, verbose=False)
		except TypeError as e:
			print("{}".format(e))


class TCPServerProcess(Process):
	def __init__(self):
		Process.__init__(self)
		self.tcpServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.tcpServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.tcpServer.bind(("192.168.1.88", 53))
		self.tcpServer.listen(500)
		self.BUFFER_SIZE = 1024
		print("TCP DNS server started on port 53")

	def terminate(self):
		print("CLOSING TCP PROCESS")
		super(TCPServerProcess, self).terminate()

	def run(self):
		while True:
			try:
				th = Thread(target=self.handleTCPRequest, args=self.tcpServer.accept())
				th.start()
			except KeyboardInterrupt:
				return
			except Exception as e:
				print("{}".format(e))
				self.terminate()

	def handleTCPRequest(self, sock, addr):
		print("{} connected".format(addr))
		if DNS_SERVER in addr[0]:
			sock.close()
			return
		data = sock.recv(self.BUFFER_SIZE)
		data = data[2:] 	#personal fix (just remove the length field from the 'scapyied' DNS packet read)
		dns = forward_client_query("TCP", data, addr)
		self.TCPSend(sock, dns) 	#send back to client the final dns response

	def TCPSend(self, sock, dns_response):
		length = len(dns_response)
		length = struct.pack(">H", length) 	#re-adding length field (2bytes BE) at the beginning of DNS packet
		final = length + str(dns_response)
		try:
			sock.sendall(str(final))
			sock.close()
		except Exception as e:
			print("{}".format(e))

def signal_handler(signal, frame):
	sys.exit(1)

if __name__ == '__main__':
	signal.signal(signal.SIGTERM, signal_handler)
	jobs = []
	jobs.append(UDPServerProcess())
	#jobs.append(TCPServerProcess())
	for j in jobs:
		j.start()
	try:
		for j in jobs:
			j.join()
	except KeyboardInterrupt:
		for j in jobs:
			if j.is_alive():
				j.terminate()

	print("CLOSING MAIN THREAD")
