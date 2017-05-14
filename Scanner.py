class Scan_Handler:
	def __init__ (self, ports=[80], threads=10, verbose=False, verbosity="low"):
		# Verbosity Settings
		self.Verbose 	= verbose
		self.Verbosity 	= verbosity_level # Can be low, Medium, High

		# Scan Options
		self.Ports = ports
		self.Threads = threads

		# Runtime Variables
		self.Running = False

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

	# To determine whether some actions can be made or not
	def Is_Running (self):
		if self.Running:
			return True
		return False

	# Update Variables Functions

	def Add_Port (self, port):
		if self.Is_Running():
			print("[!] Ports cannot be added whilst running!")
		else:
			if type(port) == int:
				if port > 0 and port <= 65535:
					self.Ports.append(port)
					print("[+] %s has been added to the list of ports!" % port)
					return True
				else:
					print("[!] Port must be a valid (0 - 65535) integer!")
			else:
				print("[!] Port must be a valid (0 - 65535) integer!")
		return False

	def Remove_Port (self, port):
		if self.Is_Running():
			print("[!] Ports cannot be removed whilst running!")
		else:
			# No need for checking the validity of the value, just check if its in the list
			# note: it shouldnt be in the list if it isn't valid anyway
			if port in self.Ports:
				self.Ports.remove(port)
				print("[-] %s has been removed from the list of ports!" % port)
				return True
			else:
				print("[!] The port wasn't in the list anyway.")
		return False
	
	def Set_Ports (self, ports):
		if self.Is_Running():
			print("[!] Ports cannot be changed whilst running!")
			return False
		else:
			# Verify whether it is a list of valid integers or not
			if type(ports) == list:
				for port in ports:
					if type(port) == int:
						if not (port > 0 and port <= 65535):
							print("[!] Ports must be a list of valid (0 - 65535) integers!")
							return False
					else:
						print("[!] Ports must be a list of valid (0 - 65535) integers!")
						return False
				self.Ports = ports
				print("[+] Ports have been updated!")
				return True
			else:
				print("[!] Ports must be a list of valid (0 - 65535) integers!")
				return False

	def Set_Threads (self, threads):
		if self.Is_Running():
			print("[!] Threads cannot be changed whilst running!")
		else:
			if type(threads) == int:
				if threads > 0:
					self.Threads = threads
					print("[+] Threads have been updated!")
					return True
				else:
					print("[!] There must be at least 1 thread!")
			else:
				print("[!] Threads must be an integer!")
		return False
