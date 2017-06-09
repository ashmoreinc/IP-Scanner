from IP import *
from queue import Queue
from socket import socket, AF_INET, SOCK_STREAM, getfqdn
from threading import Thread, Lock
from time import time, sleep
from os import path, makedirs
from urllib.request import urlopen
from urllib.error import *
from bs4 import BeautifulSoup
import subprocess


printLock = Lock()

class Scan_Handler:
	def __init__ (self, ports=[80], threads=10, verbose=False, verbosity="low", write_results=False, scan_opts = ["status", "ping", "web_title", "hostname"]):
		# Verbosity Settings
		self.Verbose 		= verbose
		self.Verbosity 		= verbosity 	# Can be low, Medium, High
		self.Do_Write		= write_results

		# Scan Options
		self.Scan_Opts 		= scan_opts # This will be what we scan, eg web_title, ping (when implemented), etc
		self.Ports 			= ports
		self.Thread_Size 	= threads

		# Runtime Variables
		self.Running 		= False
		self.Stop_Scanner 	= False
		self.que 			= Queue() 		# This will be where all the IP's are pulled from and stored to before running
		self.Threads 		= {} 			# This will be a list of threads open {"thread num":Thread}
		
		# Results
		self.Results 		= {} 			# Dictionary {"ip":{Collected Data}}

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
				for server in self.Results: # Loops through all the results

					output.writeline(str(server) + ":")

					for key in self.Results[server]:
						output.writeline("\t\t" + key + "  :  " + str(self.Results[server][key]))

					

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

	def Add_Option (self, option):
		self.Scan_Opts.append(option)
		return True

	def Remove_Option (self, option):
		if option in self.Scan_Opts:
			self.Scan_Opts.remove(option)
			return True
		return False

	def Set_Options (self, options):
		if type(options) == list:
			self.Scan_Opts = options
			return True

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

		self.open_ports = []
		self.thread = None

	# Extra Scan Functions


	def Hostname (self, server):
		try:
			hn = getfqdn(server)
		except Exception as e:
			hn = "None"

		return hn


	def ping_cmd (self, host):
	    breaklim = 10
	    proc = subprocess.Popen(["cmd", "/c", "ping", host, "-n", "3"],stdout=subprocess.PIPE, shell=True)
	    nulllines = 0
	    for line in iter(proc.stdout.readline,''):
	        if nulllines == breaklim:
	            break
	        
	        if line.decode() == "":
	            nulllines += 1
	        else:
	            nulllines = 0
	            line = line.decode().strip("\n")
	            if "Maximum" in line and "Minimum" in line and "Average" in line:
	                return line
	    return False

	def Is_Alive (self, server):
		if self.ping_cmd(server) == False:
			return False
		else:
			return True
		
	def Ping_w (self, host):
	    '''
	    Use subrpocess to ping through the console,
	    then parse the output to get the ping speed
	    
		_w means windows, linux version yet to be created
	    '''

	    found_start = False
	    start_read = False
	    buffer = ""
	    
	    line = self.ping_cmd(host)
	    if line == False:
	        return "None"
	        
	    for letter in line:
	        if not found_start:
	            
	            if len(buffer) == 7:
	                buffer = buffer[1:] + str(letter)
	            else:
	                buffer += str(letter)
	            if buffer == "Average":
	                found_start = True
	                buffer = ""
	        else:
	            if not start_read:
	                if len(buffer) == 2:
	                    buffer = buffer[1:] + letter
	                    if buffer == "= ":
	                        start_read = True
	                        buffer = ""
	                else:
	                    buffer += str(letter)
	            else:
	                    buffer += str(letter)
	    return buffer.strip("\r")

	def Web_Title (self, server):
		# Check if the http port and https port is open on the server, attempt to get title for open addresses

		if 443 in self.open_ports and 80 in self.open_ports:
			try:
				soup = BeautifulSoup(urlopen("http://" + str(server)), "html.parser")
				t80  = soup.title.string
			except HTTPError as err:
				t80  = "HTTP Error - " + str(err.code)
			except:
				t80  = "None"

			try:
				soup = BeautifulSoup(urlopen("https://" + str(server)), "html.parser")
				t443 = soup.string.title
			except HTTPError as err:
				t443  = "HTTP Error - " + str(err.code)
			except:
				t443  = "None"


			if t80 == t443:
				return t80
			else:
				return str(t80) + " / " + str(t443)
		elif 80 in self.open_ports:
			try:
				soup = BeautifulSoup(urlopen("http://" + str(server)), "html.parser")
				t80  = soup.title.string
			except HTTPError as err:
				t80  = "HTTP Error - " + str(err.code)
			except:
				t80  = "None"
				
			return str(t80)
		elif 443 in self.open_ports:
			try:
				soup = BeautifulSoup(urlopen("https://" + str(server)), "html.parser")
				t443 = soup.string.title
			except HTTPError as err:
				t443  = "HTTP Error - " + str(err.code)
			except:
				t443  = "None"

			return str(t443)
		else:
			return "None"

	# Main Scan functions

	def Scan(self, server, port):
		self.socket = socket(AF_INET, SOCK_STREAM)
		try:
			self.socket.connect((server, port))
			self.socket.close()
			return True
		except:
			self.socket.close()
			return False


	def Start_Scanning (self):
		self.thread = Thread(target=self.Run_Thread)
		self.thread.daemon = True
		self.thread.start()

	def Run_Thread(self):
		self.controller.Print_If_Verbose("high", "[+] Thread Created")
		while True:
			self.open_ports = []
			server = self.controller.que.get()
			if server is None:
				break
			if self.controller.Stop_Scanner:
				self.controller.que.task_done()
				self.controller.Print_If_Verbose("high", "IM QUITING BITCH")
				break

			self.controller.Print_If_Verbose("high", "[+] Scanning on %s has started." % server)
			
			results  = {}

			# Status
			if "status" in self.controller.Scan_Opts:
				status = self.Is_Alive(server)

				results["status"] = status 

			# Ports 
			for port in self.controller.Ports:
				if self.Scan(server, port):
					self.open_ports.append(port)

			results["ports"] = self.open_ports

			self.controller.Print_If_Verbose("low", "[+] ports %s are open on %s" % (self.open_ports, server))

			# Web_Title

			if "web_title" in self.controller.Scan_Opts: # Do we scan the web title?
				title = self.Web_Title(server)

				results["web_title"] = title

			# Hostname

			if "hostname" in self.controller.Scan_Opts:
				hostname = self.Hostname(server)

				results["hostname"] = hostname

			# Ping

			if "ping" in self.controller.Scan_Opts:
				ping = self.Ping_w(server)

				results["ping"] = ping


			# Output
			self.controller.Print_If_Verbose("high", "[+] Scanning on %s has stopped." % server)
			self.controller.Results[server] = results
			self.controller.New_Data.put([server, results])

			# Finish Up
			self.controller.que.task_done()

		self.controller.Print_If_Verbose("high", "[+] Thread Destroyed")

if __name__ == "__main__":
	Scanner = Scan_Handler(ports=[80, 443, 8000, 8080], threads=100, verbose=False, verbosity="high", write_results=True)
	Scanner.Start_Scanner("80.4.150.1", "80.4.160.0")
	for i in Scanner.Get_Outputs_Realtime():
		if str(i[1]["ports"]) != "[]" or i[1]["web_title"] != "None" or i[1]["ping"]!= "None":
			print(i)
