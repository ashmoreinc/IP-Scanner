from Scanner import *
from threading import Thread

Scanner = Scan_Handler(verbose=False, verbosity="high", threads=50, ports=[80, 443])
Scanner.Start_Scanner("192.168.0.1", "192.168.0.5")

def Background ():
	for data in Scanner.Get_Outputs_Realtime():
		print(str(data))

bg		= Thread(target=Background)
bg.daemon  	= True
bg.start()