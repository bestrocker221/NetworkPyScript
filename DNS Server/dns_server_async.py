#! /usr/bin/python
from scapy.all import *
import signal, time, sys
from threading import Thread
from multiprocessing import Process
from time import sleep
from Queue import Queue

DNS_SERVER = "8.8.8.8" 	#google dns
cache = {}	#in-memory caching

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
				if not self.new_query.empty():
					for i in range(self.new_query.qsize()):
						elem = self.new_query.get()
						tid = elem["tid"]
						qname = elem["qname"]
						raw_dns_query = elem["raw"]
						host_addr = elem["addr"]
						dns_server_response = search_cache(qname) #search response in cache
						if dns_server_response: 	#cached response
							#put response in to-send queue
							self.rcvd_query.put({ "tid":tid,
								"qname":qname, "raw":dns_server_response, "addr":host_addr})
						else: 						#non cached
							#Forward request directly to server
							req = IP(dst=DNS_SERVER)/UDP(dport=53)/raw_dns_query
							send(req, verbose=False)
						self.new_query.task_done()
				else:
					sleep(0.001) #avoid busy-waiting
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
				if not self.rcvd_query.empty(): 				#check to-send queue
					for i in range(self.rcvd_query.qsize()): 	#send every pending response
						elem = self.rcvd_query.get()
						tid = elem["tid"]
						qname = elem["qname"]
						raw_dns_query = elem["raw"]
						host_addr = elem["addr"]
						raw_dns_query.id = tid
						print("Sending " + qname + " RESPONSE to {} for {}".format(host_addr, qname))
						msg = Ether()/IP(dst=host_addr[0])/\
							UDP(sport=53,dport=host_addr[1])/raw_dns_query
						try:
							sendp(msg, verbose=False)
						except Exception as e:
							print("{}".format(e))
						self.rcvd_query.task_done()
				else:
					sleep(0.001) 	#avoid busy-waiting
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
class UDPServerProcess(Thread):
	def __init__(self, new_query, rcvd_query, who_asked_what):
		Thread.__init__(self)
		self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.server.settimeout(1)
		self.server.bind(('192.168.1.88', 53))
		self.BUFFER_SIZE = 1024
		self.new_query = new_query
		self.rcvd_query = rcvd_query
		self.who_asked_what = who_asked_what
		self.server_fw__thread = FWToServerThread(self.new_query, self.rcvd_query)
		self.client_fw_thread = FWToClientThread(self.new_query, self.rcvd_query)
		self.server_fw__thread.start()
		self.client_fw_thread.start()
		print("UDP DNS server started on port 53")
		self.go = True
	
	def terminate(self):
		print("CLOSING UDP PROCESS")
		self.client_fw_thread.stop()
		self.server_fw__thread.stop()
		self.go = False

	def who_asked(self, qname):
		elem = self.who_asked_what.get()
		if "qname" in elem:
			self.who_asked_what.task_done()
			return elem["addr"]
		else:
			self.who_asked_what.put(elem)
			raise Exception

	def run(self):
		while self.go:
			try:
				data, addr = self.server.recvfrom(self.BUFFER_SIZE)
				data = DNS(data)
				if data and data.haslayer(DNS):
					qname = data.qd.qname
					tid = data.id
					self.who_asked_what.put({"tid": tid, "qname":qname, "addr":addr})
					if data.qr == 1: 							#query response
						try:
							print("UDP [" + str(addr[0]) + ":" + str(addr[1]) +"]" + " ANSWER FOR " 
								+ str(data.qd.qname) + " --> " + str(data.an.rdata))
						except AttributeError:
							print("NONE TYPE ?? FOR " + data.qd.qname)
						real_addr = self.who_asked(qname)
						cache.update({qname:{"raw":data}})      #cache response in memory
						self.rcvd_query.put({"tid":tid,			#add new received query to dispatch
							"qname":qname,"raw":data, "addr":real_addr}) 
					elif data.qr == 0: 							#new query
						print("UDP [" + str(addr[0]) + ":" + str(addr[1]) +"]" + " REQUESTED: " + qname)
						self.new_query.put({"tid": data.id, 	#add new query to forward to server
							"qname":qname,"raw":data, "addr":addr}) 	
			except socket.timeout:
				continue
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
	new_query = Queue()
	rcvd_query = Queue()
	who_asked_what = Queue()
	srv = UDPServerProcess( new_query, rcvd_query, who_asked_what)
	srv.start()
	try:
		while True:
			sleep(1)
	except KeyboardInterrupt:
		if srv.is_alive():
			srv.terminate()
			srv.join()

	print("CLOSING MAIN THREAD")