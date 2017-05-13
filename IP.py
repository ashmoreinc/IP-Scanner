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
