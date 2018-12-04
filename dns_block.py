import pydivert
import re
from dnslib import *

regex = re.compile("DNS Question: '([^\r]*).'")
f = open("test.txt", "r")
ban_list = f.read()
f.close()

w = pydivert.WinDivert("udp.DstPort == 53 and udp.PayloadLength > 0")

w.open()

while True:
    packet = w.recv()

    dns_hdr = DNSRecord.parse(packet.udp.payload)
    #print(dns_hdr.questions)

    find_obj = regex.search('{0}'.format(dns_hdr.questions))
    host_name = find_obj.group(1)

    if host_name in ban_list:
        print("   " + host_name + "   block")
    else:
        w.send(packet)

w.close()


#[<DNS Question: 'www.google.co.kr.' qtype=A qclass=IN>]
