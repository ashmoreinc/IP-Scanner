from IP import *
from queue import Queue
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread, Lock
from time import time, sleep
from os import path, makedirs

printLock = Lock()

class Scan_Handler:
	def __init__ (self, ports=[80], threads=10, verbose=False, verbosity="low", write_results=False):
		# Verbosity Settings
		self.Verbose 		= verbose
		self.Verbosity 		= verbosity 	# Can be low, Medium, High
		self.Do_Write		= write_results

		# Scan Options
		self.Ports 			= ports
		self.Thread_Size 	= threads

		# Runtime Variables
		self.Running 		= False
		self.Stop_Scanner 	= False
		self.que 			= Queue() 		# This will be where all the IP's are pulled from and stored to before running
		self.Threads 		= {} 			# This will be a list of threads open {"thread num":Thread}
		
		# Results
		self.Open_Addresses = {} 			# Dictionary {"ip":[ports]}

		# Results Output
		self.New_Data = Queue()

	def Get_Outputs_Realtime (self):
		while True:
			try:
				data = self.New_Data.get(timeout=5)
			except:
				if not self.Running:
					break
				continue
			if data is None:
				break

			yield data
			self.New_Data.task_done()
			
			

	# Output the results if set to do so
	def Write_Results (self):
		if self.Do_Write:
			if not path.exists("Results"): # Check if the directory Results already exists, create one if not
				makedirs("Results")

			filename = "Results\\" + str(time()) + ".txt" # Set the filename to be the time (seconds) .txt, assures a unique name each time
			with open(filename, "a") as output:
				for server in self.Open_Addresses: # Loops through all the results
					ports = ""
					for port in self.Open_Addresses[server]: # Loops though all the ports format them into a string
						ports += str(port) + ","
					ports = ports[:-1] # Remove the trailing comma
					output.write(str(server) + " : " + ports) # Write

	# To check whether something should occur based of the verbosity.
	# Eg if something requires high verbosity, is the verbosity high 
	def Verbosity_Verify (self, level):
		if self.Verbose:
			if self.Verbosity == "high":
				return True
			elif self.Verbosity == "medium":
				if level in ["medium", "low"]:
					return True
			elif self.Verbosity == "low":
				if level == "low":
					return True
		return False

	def Print_If_Verbose (self, level, text):
		if self.Verbosity_Verify(level):
			with printLock:
				print(text)

	# To determine whether some actions can be made or not
	def Is_Running (self):
		if self.Running:
			return True
		return False

	# Update Variables Functions

	def Add_Port (self, port):
		if self.Is_Running():
			self.Print_If_Verbose("low", "[!] Ports cannot be added whilst running!")
		else:
			if type(port) == int:
				if port > 0 and port <= 65535:
					self.Ports.append(port)
					self.Print_If_Verbose("low", "[+] %s has been added to the list of ports!" % port)
					return True
				else:
					self.Print_If_Verbose("low", "[!] Port must be a valid (0 - 65535) integer!")
			else:
				self.Print_If_Verbose("low", "[!] Port must be a valid (0 - 65535) integer!")
		return False

	def Remove_Port (self, port):
		if self.Is_Running():
			self.Print_If_Verbose("low", "[!] Ports cannot be removed whilst running!")
		else:
			# No need for checking the validity of the value, just check if its in the list
			# note: it shouldnt be in the list if it isn't valid anyway
			if port in self.Ports:
				self.Ports.remove(port)
				self.Print_If_Verbose("low", "[-] %s has been removed from the list of ports!" % port)
				return True
			else:
				self.Print_If_Verbose("low", "[!] The port wasn't in the list anyway.")
		return False
	
	def Set_Ports (self, ports):
		if self.Is_Running():
			self.Print_If_Verbose("low", "[!] Ports cannot be changed whilst running!")
			return False
		else:
			# Verify whether it is a list of valid integers or not
			if type(ports) == list:
				for port in ports:
					if type(port) == int:
						if not (port > 0 and port <= 65535):
							self.Print_If_Verbose("low", "[!] Ports must be a list of valid (0 - 65535) integers!")
							return False
					else:
						self.Print_If_Verbose("low", "[!] Ports must be a list of valid (0 - 65535) integers!")
						return False
				self.Ports = ports
				self.Print_If_Verbose("low", "[+] Ports have been updated!")
				return True
			else:
				self.Print_If_Verbose("low", "[!] Ports must be a list of valid (0 - 65535) integers!")
				return False

	def Set_Threads (self, threads):
		if self.Is_Running():
			self.Print_If_Verbose("low", "[!] Threads cannot be changed whilst running!")
		else:
			if type(threads) == int:
				if threads > 0:
					self.Threads_Size = threads
					self.Print_If_Verbose("low", "[+] Threads have been updated!")
					return True
				else:
					self.Print_If_Verbose("low", "[!] There must be at least 1 thread!")
			else:
				self.Print_If_Verbose("low", "[!] Threads must be an integer!")
		return False

	# Scanning

	def Stop_Scanning (self):
		self.Stop_Scanner = True
		sleep(0.25) # Allow for those threads that may have just started a new round
		while True:
			try:
				x = self.que.get(block=None, timeout=2)
			except:
				break
			if x is None:
				break
			self.que.task_done()
		self.Print_If_Verbose("medium", "[*] Scan has completely finished")

	def Start_Scanner (self, _from, _to):
		# Use this as a thread so that it can run while the user does what ever
		thread = Thread(target=self.Start_Scanner_Thread, args=(_from, _to))
		thread.daemon = True
		thread.start()

	def Start_Scanner_Thread (self, _from, _to):
		# Check if the inputs are in the IP data type. Convert if not.
		if type(_from) != IPV4:
			_from = IPV4(ip=_from)
		if type(_to) != IPV4:
			_to = IPV4(ip=_to)

		self.Print_If_Verbose("low", "[+] Scan Started")

		self.Running = True
		self.que = Queue() # Reset the Queue
		self.New_Data = Queue() # Reset the New_Data Queue

		# Loops through all the addresses untill _from matches _to
		while True:
			self.que.put(_from.Get_As_String())
			if _from == _to:
				break
			else:
				_from.Next_IP()

		self.Print_If_Verbose("high", "[+] Creating Threads")

		self.Threads = {} # Reset the Threads
		for thread in range(self.Thread_Size):
			self.Threads[thread] = Scanner_Thread(self, thread)
			self.Threads[thread].daemon = True
			self.Threads[thread].Start_Scanning()

		self.que.join()
		for _ in range(self.Thread_Size + 1):
			self.que.put(None)

		for thread in self.Threads:
			self.Threads[thread].thread.join()

		self.Running = False
		self.Stop_Scanner = False

		self.New_Data.join()
		self.New_Data.put(None)
		
		self.Write_Results()
		

class Scanner_Thread:
	def __init__ (self, controller, num):
		self.controller = controller # For reference
		self.Thread_Num = num

		self.socket = socket(AF_INET, SOCK_STREAM) # For scanning

		self.thread = None

	def Scan(self, server, port):
		try:
			self.socket.connect((server, port))
			return True
		except:
			return False

	def Start_Scanning (self):
		self.thread = Thread(target=self.Run_Thread)
		self.thread.daemon = True
		self.thread.start()

	def Run_Thread(self):
		self.controller.Print_If_Verbose("high", "[+] Thread Created")
		while True:
			open_ports = []
			server = self.controller.que.get()
			if server is None:
				break
			if self.controller.Stop_Scanner:
				self.controller.que.task_done()
				self.controller.Print_If_Verbose("high", "IM QUITING BITCH")
				break
			self.controller.Print_If_Verbose("high", "[+] Scanning on %s has started." % server)
			for port in self.controller.Ports:
				if self.Scan(server, port):
					open_ports.append(port)

			self.controller.Print_If_Verbose("high", "[+] Scanning on %s has stopped." % server)

			if len(open_ports) > 0:
				self.controller.Open_Addresses[server] = open_ports
				self.controller.New_Data.put([server, open_ports])
				self.controller.Print_If_Verbose("low", "[+] ports %s are open on %s" % (open_ports, server))

			self.controller.que.task_done()
		self.controller.Print_If_Verbose("high", "[+] Thread Destroyed")

if __name__ == "__main__":
	Scanner = Scan_Handler(verbose=False, verbosity="high", write_results=True)
	Scanner.Start_Scanner("192.168.0.1", "192.168.0.200")
	for i in Scanner.Get_Outputs_Realtime():
		print(i)
	#print(Scanner.Open_Addresses)
