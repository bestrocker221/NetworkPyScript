#! /usr/bin/python
from scapy.all import *
import signal, time, sys
from threading import Thread
from multiprocessing import Process
from time import sleep
from Queue import Queue

DNS_SERVER = "8.8.8.8" 	#google dns
cache = {}	#in-memory caching
#new_query = {}
#rcvd_query = {}

def search_cache(hostname):	
	if hostname in cache.keys():
		return cache[hostname]["raw"]

class FWToServerThread(Thread):
	def __init__(self, new_query, rcvd_query):
		Thread.__init__(self)
		self.go = True
		self.new_query = new_query
		self.rcvd_query = rcvd_query
		print("FWToServerThread Started")

	def stop(self):
		self.go = False

	def terminate(self):
		print("CLOSING FWToServerThread")

	def run(self):
		while self.go:
			try:
				print("NEW QUERY IS EMPTY?: " + str(self.new_query.empty()))
				if not self.new_query.empty():
					print("NEW QUERY > 0")
					for i in self.new_query.qsize():
						elem = self.new_query.get()
						qname = elem["qname"]
						raw_dns_query = elem["raw"]
						host_addr = elem["addr"]
						dns_server_response = search_cache(qname)
						if dns_server_response: 	#cached response
							self.rcvd_query.put({"qname":qname, "raw":dns_server_response, "addr":host_addr})
						else: 						#non cached
							req = IP(dst=DNS_SERVER)/UDP(dport=53)/raw_dns_query
							send(req, verbose=False)
						elem.task_done()
				else:
					sleep(2.01)
			except KeyboardInterrupt:
				return
			except Exception as e:
				print("{}".format(e))
				self.terminate()
		self.terminate()

class FWToClientThread(Thread):
	def __init__(self, new_query, rcvd_query):
		Thread.__init__(self)
		self.go = True
		self.new_query = new_query
		self.rcvd_query = rcvd_query
		print("FWToClientThread Started")

	def terminate(self):
		print("CLOSING FWToClientThread")

	def stop(self):
		self.go = False

	def run(self):
		while self.go:
			try:
				print("RCV QUERY IS EMPTY?: " + str(self.rcvd_query.empty()))
				if not self.rcvd_query.empty():
					print("RCVD QUERY > 0")
					for i in self.rcvd_query.qsize():
						elem = self.rcvd_query.get()
						qname = elem["qname"]
						raw_dns_query = elem["raw"]
						host_addr = elem["addr"]
						msg = Ether()/IP(dst=host_addr[0])/UDP(sport=53,dport=host_addr[1])/raw_dns_query
						try:
							sendp(msg, verbose=False)
						except Exception as e:
							print("{}".format(e))
						elem.task_done()
				else:
					sleep(2.01)
			except KeyboardInterrupt:
				return
			except Exception as e:
				print("{}".format(e))
				self.terminate()
		self.terminate()


#Queue style
#{	
#	"qname":qname,
#	"raw":raw,
#	"addr": addr
#}
class UDPServerProcess(Process):
	def __init__(self):
		Process.__init__(self)
		self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.server.bind(('192.168.1.88', 53))
		self.BUFFER_SIZE = 1024
		self.new_query = Queue()
		self.rcvd_query = Queue()
		self.server_fw__thread = FWToServerThread(self.new_query, self.rcvd_query)
		self.client_fw_thread = FWToClientThread(self.new_query, self.rcvd_query)
		self.server_fw__thread.start()
		self.client_fw_thread.start()
		print("UDP DNS server started on port 53")
	
	def terminate(self):
		print("CLOSING UDP PROCESS")
		self.client_fw_thread.stop()
		self.server_fw__thread.stop()
		super(UDPServerProcess, self).terminate()

	def run(self):
		while True:
			try:
				data, addr = self.server.recvfrom(self.BUFFER_SIZE)
				if DNS_SERVER in addr[0]: 	#query FROM server? dischard
					continue
				data = DNS(data)
				if data and data.haslayer(DNS):
					qname = data.qd.qname
					#data.show()
					if data.qr == 1: #query response
						try:
							print("UDP [" + str(addr[0]) + ":" + str(addr[1]) +"]" + " ANSWER FOR " 
								+ str(data.qd.qname) + " --> " + str(data.an.rdata))
						except AttributeError:
							print("NONE TYPE ?? FOR " + data.qd.qname)
						print("CACHING " +str(qname))
						cache.update({qname:{"raw":data}})      #cache response in memory
						self.rcvd_query.put({"qname":qname,"raw":data, "addr":addr}) #add new received query to dispatch
						#print("now RCVD IS {}".format(self.rcvd_query))
					elif data.qr == 0: #new query
						print("UDP [" + str(addr[0]) + ":" + str(addr[1]) +"]" + " REQUESTED: " + qname)
						self.new_query.put({"qname":qname,"raw":data, "addr":addr}) 	#add new query to forward to server
						print("ELEMENTO AGGIUNTO A NEW QUERY. SIZE: " + str(self.new_query.qsize()))
						#print("NOW NEW QUERY IS : {}".format(self.new_query))

			except AttributeError as a:
				print("{}".format(a))
			except KeyboardInterrupt:
				self.terminate()
			except Exception as e:
				print("{}".format(e))
				self.terminate()
		self.terminate()

def signal_handler(signal, frame):
	sys.exit(1)

if __name__ == '__main__':
	signal.signal(signal.SIGTERM, signal_handler)
	srv = UDPServerProcess()
	srv.start()
	try:
		srv.join()
	except KeyboardInterrupt:
		if srv.is_alive():
			srv.terminate()

	print("CLOSING MAIN THREAD")