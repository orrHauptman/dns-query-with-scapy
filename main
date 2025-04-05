from scapy.all import IP, UDP, DNS, DNSQR, sr1

wanted_address: str = input("Please enter the name of the wanted website \n")

dns_packet = IP(dst="8.8.8.8")/UDP(sport=2880,dport=53)/DNS(qdcount=1,rd=1)/DNSQR(qname=wanted_address)

received_packet = sr1(dns_packet)


if received_packet and received_packet.haslayer(DNS) and received_packet[DNS].ancount > 0:
    for i in range(len(received_packet[DNS])):
        if  received_packet[DNS].an[i].type == 1:  # A
            print("IP:",  received_packet[DNS].an[i].rdata)
            break
    else:
        print("No A record found in DNS response.")
else:
    print("No DNS response received.")
