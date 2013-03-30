#!/usr/bin/env python

# Simple script to generate a lot of neighbors. This uses scapy. It
# needs a version of Scapy that contains an LLDP dissector. There is
# one in the scapy community repository:
#  https://hg.secdev.org/scapy-com/file/dc0876d1c302/scapy/layers/lldp.py

from scapy.all import *
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-o", "--output", dest="output",
                  help="write PCAP file to FILE", metavar="FILE",
                  default="out.pcap")
parser.add_option("-n", "--neighbors", dest="neighbors",
                  help="generate N neighbors", metavar="N",
                  default=60, type="int")

(options, args) = parser.parse_args()

wrpcap(options.output,
       [Ether(dst="01:80:c2:00:00:0e", src="00:17:d1:a8:35:be")/
        LLDP(tlvlist=[LLDPChassisId(subtype="Locally assigned", value="titi-%03d" % i),
                      LLDPPortId(subtype="Interface name", value="eth0"),
                      LLDPTTL(seconds=120),
                      LLDPDUEnd()])
        for i in range(options.neighbors)])

# The generated pcap can be replayed with tcpreplay:
#  tcpreplay -i veth0 -t out.pcap
