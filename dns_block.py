import pydivert
import re
from dnslib import *

ban_site = re.compile("naver.com")

w = pydivert.WinDivert("udp.DstPort == 53 and udp.PayloadLength > 0")

w.open()

while True:
    packet = w.recv()

    dns_hdr = DNSRecord.parse(packet.udp.payload)
    print(dns_hdr.questions)

    host_name = '{0}'.format(dns_hdr.questions)
    
    search_site = ban_site.search(host_name)
    if search_site != None:
        print("dns block")
    else:
        w.send(packet)

w.close()
