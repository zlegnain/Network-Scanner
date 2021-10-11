import socket
from scapy.all import ARP, Ether, srp




def scan(devices=[]):
	"""returns devices = [{IP:XXX.XXX.XXX, MAC:ff:ff:ff:ff:ff:ff},....]

	This function will scan all devices on the local network, and 
	send an ARP request. The devices will respond, and during their
	response the function will sniff their MAC and IP addresses
	"""

	# Retrieving network range
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.connect(("8.8.8.8", 80))
	Ip_range = sock.getsockname()[0] + '/24'

	# arp packet
	arp = ARP(pdst=Ip_range)

	# Ethernet Frame packet
	e = Ether(dst="ff:ff:ff:ff:ff:ff")

	# some formating
	p = e/arp

	# getting responses from devices
	responses = srp(p, timeout=1, verbose=0)[0]

	# loop through our response packet, and store IP, and MAC addresses
	for response in responses:
		devices.append({'IP': response[1].psrc, 'Mac': response[1].hwsrc})



	return devices



if __name__ == '__main__':
	
	devices = scan()

	print("IP                       MAC")
	print("----------------------------------")
	for device in devices:
		print(device['IP']+'      '+device['Mac'])



