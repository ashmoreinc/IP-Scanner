class IPV4:
	def __init__(self, ip="127.0.0.1"):
		# Ip is to be stored as an array

		# Check the data type of the IP input
		if type(ip) == str:
			self.Current_IP = self.Convert_STA(ip)
		elif type(ip) == list:
			self.Current_IP = type(ip)


		# Verify The IPs validity
		if not self.Verify_IP():
			raise TypeError("Ip must be a string or array with 4 places (separated by \".\" if string).\n\te.g. \"192.168.0.1\", or [192, 168, 0, 1]")

	def Convert_ATS(self, ip):
		# Convert anm array IP into a string
		output = ""
		for place in ip:
			output += str(place) + "."
		output = output[:-1] # Remove the trailing "."
		return output

	def Convert_STA(self, ip):
		# Convert a string IP into an array
		output = []
		temp = ""
		for char in ip:
			if char == ".":
				output.append(int(temp))
				temp = ""
			else:
				temp += char
		output.append(int(temp)) # Run one last time because there is no trailing ".
		return output

	def Verify_IP (self):
		if self.Current_IP == str:
			test = self.Convert_To_Array(self.Current_IP)
		else:
			test = self.Current_IP
		# Check Length
		if len(test) > 4:
			return False

		# Check each value fits the the range (0-255)
		for place in test:
			if place > 255:
				return False
			elif place < 0:
				return False

		return True

	def Next_IP (self):
		output = self.Current_IP
		#	Check the last position
		if output[3] < 255:
			output[3] += 1
		else:
			output[3] = 0
			# Check the penultimate position
			if output[2] < 255:
				output[2] += 1
			else:
				output[2] = 0
				# Check 2nd position
				if output[1] < 255:
					output[1] += 1
				else:
					output[1] = 0
					# Check 1st position
					if output[0] < 255:
						output[0] += 1
					else:
						return False
		self.Current_IP = output
		return True

	# Expressional Operators below

	def __gt__ (self, IP2): # this > other
		# Check if compared to another IP
		if type(IP2) != IPV4:
			raise TypeError("IP's can only be compared with another IP.")
		this_ip = self.Current_IP
		that_ip = IP2.Current_IP

		# Check if both values are verified
		if not self.Verify_IP():
			raise TypeError("This IP has an invalid format")
		if not IP2.Verify_IP():
			raise TypeError("Second IP has an invalid format")

		# Loop through each place in the IP, if gt return true, if equal move on to the next index
		for index in range(4):
			if this_ip[index] > that_ip[index]:
				return True
			elif that_ip[index] > this_ip[index]:
				return False

		# At this point both values should be equal so return False
		return False

	def __ge__ (self, IP2): # this >= other
		# Check if compared to another IP
		if type(IP2) != IPV4:
			raise TypeError("IP's can only be compared with another IP.")
		this_ip = self.Current_IP
		that_ip = IP2.Current_IP

		# Check if both values are verified
		if not self.Verify_IP():
			raise TypeError("This IP has an invalid format")
		if not IP2.Verify_IP():
			raise TypeError("Second IP has an invalid format")

		# Loop through each place in the IP, if gt return true, if equal move on to the next index
		for index in range(4):
			if this_ip[index] > that_ip[index]:
				return True
			elif that_ip[index] > this_ip[index]:
				return False

		# At this point both values should be equal so return True
		return True

	def __le__ (self, IP2): # this <= other
		# Check if compared to another IP
		if type(IP2) != IPV4:
			raise TypeError("IP's can only be compared with another IP.")
		this_ip = self.Current_IP
		that_ip = IP2.Current_IP

		# Check if both values are verified
		if not self.Verify_IP():
			raise TypeError("This IP has an invalid format")
		if not IP2.Verify_IP():
			raise TypeError("Second IP has an invalid format")

		# Loop through each place in the IP, if gt return true, if equal move on to the next index
		for index in range(4):
			if this_ip[index] < that_ip[index]:
				return True
			elif that_ip[index] < this_ip[index]:
				return False

		# At this point both values should be equal so return True
		return True

	def __lt__ (self, IP2): # this < other
		# Check if compared to another IP
		if type(IP2) != IPV4:
			raise TypeError("IP's can only be compared with another IP.")
		this_ip = self.Current_IP
		that_ip = IP2.Current_IP

		# Check if both values are verified
		if not self.Verify_IP():
			raise TypeError("This IP has an invalid format")
		if not IP2.Verify_IP():
			raise TypeError("Second IP has an invalid format")

		# Loop through each place in the IP, if gt return true, if equal move on to the next index
		for index in range(4):
			if this_ip[index] < that_ip[index]:
				return True
			elif that_ip[index] < this_ip[index]:
				return False

		# At this point both values should be equal so return True
		return False

	def __eq__ (self, IP2): # this == other
		# Check if compared to another IP
		if type(IP2) != IPV4:
			raise TypeError("IP's can only be compared with another IP.")
		this_ip = self.Current_IP
		that_ip = IP2.Current_IP

		# Check if both values are verified
		if not self.Verify_IP():
			raise TypeError("This IP has an invalid format")
		if not IP2.Verify_IP():
			raise TypeError("Second IP has an invalid format")

		# Loop through each place in the IP, if gt return true, if equal move on to the next index
		for index in range(4):
			if this_ip[index] > that_ip[index]:
				return False
			elif that_ip[index] > this_ip[index]:
				return False

		# At this point both values should be equal so return True
		return True