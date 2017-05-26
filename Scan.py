from Scanner import *
import sys

'''
Arguments:

-h 		Help
-t 		Threads
-v 		Verbose
-vl 	Verbosity
-w		Write
-o		Scan Options
-p		Ports

'''

global kwargs
kwargs = {}


def Input_To_Array (uinput, dataType):
	uinput = uinput.replace("[", "").replace("]", "").replace(" ", "")
	
	buffer = ""

	output = []

	for letter in uinput:
		if letter == ",":
			try:
				output.append(dataType(buffer))
			except:
				if dataType == int:
					print("All list items must be an integer.")
				elif dataType == str:
					print("All list items must be a string.")
				else:
					print(str(buffer) + " is the wrong data type for the list.")

				exit()
			buffer = ""
		else:
			buffer += letter
	output.append(dataType(buffer))

	return output

def Parse (indicator, data=None):
	if indicator[0] != "-":
		print("There's an error, check your inputs!")
		exit()

	if indicator == "-h":
		Help()
		exit()
	elif indicator == "-t":
		try:
			kwargs["threads"] = int(data)
		except:
			print("An error occured while parsing the -t input, check your input and try again.")
			exit()
	elif indicator == "-v":
		if data.lower() == "true":
			kwargs["verbose"] = True
		elif data.lower() == "false":
			kwargs["verbose"] = False
		else:
			print("verbosity can only be true or false.")
			exit()
	elif indicator == "-vl":
		if data.lower() in ["low", "medium", "high"]:
			kwargs["verbosity"] = data.lower()
		else:
			print("Werbosity can only be low, medium or high")
	elif indicator == "-w":
		if data.lower() == "true":
			kwargs["write_results"] = True
		elif data.lower() == "false":
			kwargs["write_results"] = False
		else:
			print("Write results can only be true or false.")
			exit()
	elif indicator == "-o":
		kwargs["scan_opts"] = Input_To_Array(data, str)
	elif indicator == "-p":
		kwargs["ports"] = Input_To_Array(data, int)

def Help ():
	print("Usage: Scan.py from too arguments")
	print()
	print("Arguments: ")
	print()
	print("-h\t\tDisplay this menu")
	
	print("-t\t\tSet the number of threads")
	print("\t\tExample: -t 100")

	print("-v\t\tSet the verbosity")
	print("\t\tExample: -v true/false")

	print("-vl\t\tSet the verbosity level")
	print("\t\tExample: -vl high/medium/low")

	print("-w\t\tSet whether to write the output to a file or not")
	print("\t\tExample: -w true/false")

	print("-o\t\tWhat do you want to be scanned")
	print("\t\tExample: -o \"[status, ping, web_title, hostname]\"")
	print("\t\tNote: the quotation marks are required, you can use all or none of these options")

	print("-p\t\t:Ports to scan. Defaults to just 80 if empty")
	print("\t\tExample: -p \"[80, 443]\"")
	print("\t\tNote: the quotation marks are required, you can use all or none of these options")

	exit()

if __name__ == "__main__":
	args = sys.argv[1:]
	
	if "-h" in args:
		Help()

	_from = args[0]
	to    = args[1]

	for index in range(len(args)): # Skip the first two arguements
		if index <= 1:
			continue
		else:
			if args[index][0] == "-":
				try:
					Parse(args[index], args[index+1])
				except Exception as e:
					print(str(e))
					print("Your last input does not contain a(ny) value(s)")
					exit()
	
	print(kwargs)

	try:
		Scanner = Scan_Handler(**kwargs)
		Scanner.Start_Scanner(_from, to)
		for i in Scanner.Get_Outputs_Realtime():
			print(i)
	except KeyboardInterrupt:
		Scan_Handler.Stop_Scanning()
		exit()
