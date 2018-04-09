import socket

UDPSock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)


listen_addr = ("",8000)
UDPSock.bind(listen_addr)

newnew1 = 0
d={}
prev_eth=0
prev_dst=0
while True:
		        
		data,addr = UDPSock.recvfrom(1024)
		new1 = data.strip()
		#new11 = new1-newnew1
		new11,eth,dst = new1.split(",")
		#print new11
		# print (eth,"--->",dst)

		if (eth,dst) in d:
			value= d[eth,dst]
			new2= int(new11)
			d[eth,dst]=new2
				
			if((new2-value)>5):
				#print("diff is",(new2-value))
				if(not((eth==prev_dst)and(dst==prev_eth))):				
						prev_eth=eth
						prev_dst=dst
					
						print("Intrusion Detected")
						print("Intrusion from",eth,"to", dst)

		else:
			d[eth,dst]=int(new11)

