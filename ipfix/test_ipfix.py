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
from ipfix import IPFIX, Template

from framework import VppTestCase, VppTestRunner
from util import ppp
from random import randint

class TestIPFIXTemplate(VppTestCase):
    """ IPFIX template test case """ # test names are required

    @classmethod
    def setUpClass(cls):
        super(TestIPFIXTemplate, cls).setUpClass()
        cls.create_pg_interfaces(range(2))  # create pg0 and pg1
        for i in cls.pg_interfaces:
            i.admin_up()  # put the interface upsrc_if
            i.config_ip4()  # configure IPv4 address on the interface
            i.resolve_arp()  # resolve ARP, so that we know VPP MAC

    def setUp(self):
        super(TestIPFIXTemplate, self).setUp()
        # FIXME: I can't figure out how to get the test framework to call the
        #        IPFIX plugin's API instead of using the CLI like this
        self.logger.info(self.vapi.ppcli("set ipfix ip collector " + self.pg0.remote_ip4))
        self.logger.info(self.vapi.ppcli("set ipfix ip exporter " + self.pg1.remote_ip4))
        self.logger.info(self.vapi.ppcli("ipfix flow-meter " + self.pg1.name))

    def test_template(self):
        self.logger.info(self.vapi.ppcli("set ipfix timeout template 1"))

        self.pg0.enable_capture()
        self.pg1.enable_capture()
        self.pg_start()
        # no packets on pg1 since we didn't inject any packets
        self.pg1.assert_nothing_captured()
        # expect 3 template pkt, 1/sec
        capture = self.pg0.get_capture(timeout = 3, expected_count = 3)
        self.verify_template(self.pg0, self.pg1, capture)

    def verify_template(self, collector_if, exporter_if, capture):
        for packet in capture:
            try:
                ip = packet[IP]
                udp = packet[UDP]
                ipfix = packet[IPFIX]
                self.assert_equal(ip.src, exporter_if.remote_ip4,
                                  "exporter ip")
                self.assert_equal(ip.dst, collector_if.remote_ip4,
                                  "collector ip")
                self.assert_equal(udp.dport, 4739)
                self.assert_equal(ipfix.version, 10)
                # check that there's an IPFIX template
                self.assert_equal(ipfix[Template].templateID, 256)
            except IndexError:
                self.logger.error(ppp("Invalid packet:", packet))
                raise
            except AssertionError:
                self.logger.error(ppp("Unexpected packet:", packet))
                raise

class TestIPFIXData(VppTestCase):
    """ IPFIX data test case """

    @classmethod
    def setUpClass(cls):
        super(TestIPFIXData, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def setUp(self):
        super(TestIPFIXData, self).setUp()
        self.logger.info(self.vapi.ppcli("set ipfix ip collector " + self.pg0.remote_ip4))
        self.logger.info(self.vapi.ppcli("set ipfix ip exporter " + self.pg1.remote_ip4))
        self.logger.info(self.vapi.ppcli("ipfix flow-meter " + self.pg1.name))

    def test_basic(self):
        self.logger.info(self.vapi.ppcli("set ipfix timeout template 20"))
        self.logger.info(self.vapi.ppcli("set ipfix timeout idle 3"))

        packet_count = 10
        packets = self.create_stream(self.pg0, self.pg1, packet_count)

        self.pg0.add_stream(packets)
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        self.pg_start()

        capture1 = self.pg1.get_capture(timeout = 2, expected_count = packet_count)
        # with the timeout above, we expect to get just a data packet
        capture0 = self.pg0.get_capture(timeout = 5, expected_count = 1)
        self.verify_capture(self.pg0, self.pg1, capture0)

    def verify_capture(self, collector_if, exporter_if, capture):
        for packet in capture:
            try:
                ip = packet[IP]
                udp = packet[UDP]
                ipfix = packet[IPFIX]
                self.assert_equal(ip.src, exporter_if.remote_ip4,
                                  "exporter ip")
                self.assert_equal(ip.dst, collector_if.remote_ip4,
                                  "collector ip")
                self.assert_equal(udp.dport, 4739)
                self.assert_equal(ipfix.version, 10)
            except IndexError:
                self.logger.error(ppp("Invalid packet:", packet))
                raise
            except AssertionError:
                self.logger.error(ppp("Unexpected packet:", packet))
                raise

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
                 UDP(sport=7777, dport=5678) /
                 Raw(payload))
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            packets.append(p)

        # return the created packet list
        return packets

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
