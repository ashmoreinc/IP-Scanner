# IP-Scanner
IP-Scanner in pure python.

IP.py: A module which holds a new data type (IPV4) to store IPV4 addresses, allowing for comparisons, moving onto the next ip and verifying whether the IP that has been used/input is valid.

Scanner.py: A module which holds an object in which will control all of the running of the Scanner.

How to use:
Create the Scan handler: 	Scanner = Scan_Handler(**kwargs)
							**kwargs can be:
									ports: 		Array of ports to scan, 
									threads: 	threads to use
									Verbose:	Do extra printing? True/False
									Verbosity:	The level of verbosity ("low", "medium", "high")
Start running the scanner:	Scanner.Start_Scanner(ip_from, ip_to)
Output the result:			print(Scanner.Open_Addresses)