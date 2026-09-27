import os
import sys
import types
import unittest

# flow_control.py imports ryu at module level. Stub it out so these tests can
# run without ryu (or Mininet/Snort) installed.
if "ryu" not in sys.modules:
    ryu_ether = types.ModuleType("ryu.ofproto.ether")
    ryu_ether.ETH_TYPE_IP = 0x0800
    ryu_ether.ETH_TYPE_ARP = 0x0806
    ryu_ether.ETH_TYPE_LLDP = 0x88CC
    ryu_ether.ETH_TYPE_MPLS = 0x8847
    ryu_ether.ETH_TYPE_IPV6 = 0x86DD

    ryu_inet = types.ModuleType("ryu.ofproto.inet")
    ryu_inet.IPPROTO_ICMP = 1
    ryu_inet.IPPROTO_TCP = 6
    ryu_inet.IPPROTO_UDP = 17
    ryu_inet.IPPROTO_SCTP = 132

    sys.modules["ryu"] = types.ModuleType("ryu")
    sys.modules["ryu.ofproto"] = types.ModuleType("ryu.ofproto")
    sys.modules["ryu.ofproto.ether"] = ryu_ether
    sys.modules["ryu.ofproto.inet"] = ryu_inet

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flow_control import TrackConnection


class TestConnTrackDict(unittest.TestCase):
    def setUp(self):
        self.track = TrackConnection()

    def test_new_source_ip_creates_single_entry_tuple(self):
        result = self.track.conn_track_dict({}, "10.0.0.1", "10.0.0.2", 1234, 80, "UNREPLIED", 1)
        self.assertEqual(result, {"10.0.0.1": (("10.0.0.2", 1234, 80, "UNREPLIED"),)})

    def test_duplicate_entry_not_added_twice(self):
        dic = {}
        dic = self.track.conn_track_dict(dic, "10.0.0.1", "10.0.0.2", 1234, 80, "UNREPLIED", 1)
        dic = self.track.conn_track_dict(dic, "10.0.0.1", "10.0.0.2", 1234, 80, "UNREPLIED", 1)
        self.assertEqual(dic["10.0.0.1"], (("10.0.0.2", 1234, 80, "UNREPLIED"),))

    def test_distinct_entry_appended_for_existing_source_ip(self):
        dic = {}
        dic = self.track.conn_track_dict(dic, "10.0.0.1", "10.0.0.2", 1234, 80, "UNREPLIED", 1)
        dic = self.track.conn_track_dict(dic, "10.0.0.1", "10.0.0.3", 5555, 443, "UNREPLIED", 1)
        self.assertEqual(
            dic["10.0.0.1"],
            (
                ("10.0.0.2", 1234, 80, "UNREPLIED"),
                ("10.0.0.3", 5555, 443, "UNREPLIED"),
            ),
        )

    def test_bidirectional_var_2_inserts_reverse_entry(self):
        dic = self.track.conn_track_dict({}, "10.0.0.1", "10.0.0.2", "PING", "PONG", "PONG", 2)
        self.assertEqual(dic["10.0.0.1"], (("10.0.0.2", "PING", "PONG", "PONG"),))
        self.assertEqual(dic["10.0.0.2"], (("10.0.0.1", "PONG", "PING", "PONG"),))


if __name__ == "__main__":
    unittest.main()
