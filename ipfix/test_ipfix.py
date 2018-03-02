#!/usr/bin/env python

# Unit tests for IPFIX plugin
#
# How to run
# ----------
# Since the plugin is out of the VPP tree, running the tests has extra steps.
#
# To run tests in general in the VPP working dir:
#   $ make test
#
# Now to run for this plugin:
#   $ make test EXTERN_TESTS=<path-to-plugin>/ipfix
#
# To only run this particular test:
#   $ make test TEST=test_ipfix EXTERN_TESTS=<path-to-plugin>/ipfix \
#               EXTERN_PLUGIN=/usr/lib/vpp_plugins
#
# To help debug the tests, you can supply a verbosity flag, e.g., "V=1"

import unittest

from scapy.packet import Raw
from scapy.layers.inet import IP, UDP, Ether

from framework import VppTestCase, VppTestRunner
from random import randint

class TestIPFIX(VppTestCase):
    """ IPFIX test case """ # test names are required

    @classmethod
    def setUpClass(cls):
        super(TestIPFIX, cls).setUpClass()
        cls.create_pg_interfaces(range(2))  # create pg0 and pg1
        for i in cls.pg_interfaces:
            i.admin_up()  # put the interface upsrc_if
            i.config_ip4()  # configure IPv4 address on the interface
            i.resolve_arp()  # resolve ARP, so that we know VPP MAC

    def setUp(self):
        super(TestIPFIX, self).setUp()
        self.logger.info(self.vapi.ppcli("set ipfix timeout idle 1 timeout template 1 timeout active 1"))
        self.logger.info(self.vapi.ppcli("set ipfix ip collector " + self.pg0.remote_ip4))
        self.logger.info(self.vapi.ppcli("set ipfix ip exporter " + self.pg1.remote_ip4))
        self.logger.info(self.vapi.ppcli("ipfix flow-meter " + self.pg1.name))

    def test_basic(self):
        packet_count = 10
        packets = self.create_stream(self.pg0, self.pg1, packet_count)

        self.pg0.add_stream(packets)
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        self.pg_start()

        capture1 = self.pg1.get_capture(timeout = 1, expected_count = packet_count)
        capture0 = self.pg0.get_capture(timeout = 5, expected_count = 2)

    # copied from example test in docs
    def create_stream(self, src_if, dst_if, count):
        packets = []
        for i in range(count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=randint(1000, 2000), dport=5678) /
                 Raw(payload))
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            packets.append(p)

        # return the created packet list
        return packets

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
