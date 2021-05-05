#! usr/bin/env python
import logging
from ryu.ofproto.ether import ETH_TYPE_IP, ETH_TYPE_ARP, ETH_TYPE_LLDP, ETH_TYPE_MPLS, ETH_TYPE_IPV6
from ryu.ofproto.inet import IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP


class SwitchInfo:
    '''
    Handles information of connected switch
    '''
    def __init__(self, event):
        switch = event.dp
        if event.enter:
            self.__switch_connected(switch)
        else:
            self.__switch_disconnected(switch)

    def __switch_connected(self, sw):
        ResetSwitch(sw)

    def __switch_disconnected(self, sw):
        logging.info("Switch %s has disconnected from OFP 1.3", sw.id)


class ResetSwitch:
    '''
    Resets the connected switch
    '''
    def __init__(self, dp):
        self.__reset_switch(dp)

    def __reset_switch(self, dp):
        assert (dp is not None), "Datapath object is not set"

        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        flow_mod = dp.ofproto_parser.OFPFlowMod(dp, 0, 0, 0,
                                                ofproto.OFPFC_DELETE,
                                                0, 0, 1,
                                                ofproto.OFPCML_NO_BUFFER,
                                                ofproto.OFPP_ANY,
                                                ofproto.OFPG_ANY,
                                                )
        logging.info("Delete all entries in flow table")
        dp.send_msg(flow_mod)

        const = Construct()

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        const.add_flow(datapath=dp, actions=actions, priority=0)

        actions = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
        const.add_flow(datapath=dp, actions=actions, priority=10000, eth_type=ETH_TYPE_LLDP)


class Construct:
    '''
    Constructs the matching object from packets' field
    If no parameters - the returned value matches everything
    '''

    def __init__(self):
        logging.info("Rule construction")

    def add_flow(self, datapath, actions, priority=1000, in_port=None, eth_dst=None,
                 eth_src=None, eth_type=None, ip_proto=None, ipv4_src=None, ipv4_dst=None,
                 tcp_src=None, tcp_dst=None, udp_src=None, udp_dst=None, icmpv4_type=None, idle_timeout=1800):

        assert (datapath is not None), "Datapath Object is Not set"
        assert (actions is not None), "Actions Object is Not set"

        parser = datapath.ofproto_parser

        flow_match = FlowAdd()
        match = parser.OFPMatch()

        if eth_type is not None:
            if eth_type == ETH_TYPE_IP:
                if ip_proto is not None:

                    if ip_proto == IPPROTO_ICMP:
                        match = parser.OFPMatch(in_port=in_port, eth_type=eth_type, ip_proto=ip_proto,
                                                icmpv4_type=icmpv4_type, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
                    elif ip_proto == IPPROTO_TCP:
                        match = parser.OFPMatch(in_port=in_port, eth_type=eth_type, ip_proto=ip_proto,
                                                ipv4_src=ipv4_src, ipv4_dst=ipv4_dst,
                                                tcp_src=tcp_src, tcp_dst=tcp_dst)
                    elif ip_proto == IPPROTO_UDP:
                        match = parser.OFPMatch(in_port=in_port, eth_type=eth_type, ip_proto=ip_proto,
                                                ipv4_src=ipv4_src, ipv4_dst=ipv4_dst,
                                                udp_src=udp_src, udp_dst=udp_dst)
                    else:
                        logging.info("Check OFPMatch ip_proto parameter")
                else:
                    logging.info("Set OFPMatch ip_proto parameter")
            elif eth_type == ETH_TYPE_ARP:
                logging.info("ARP object is set")
                match = parser.OFPMatch(in_port=in_port, eth_type=eth_type, eth_src=eth_src, eth_dst=eth_dst)
            elif eth_type == ETH_TYPE_LLDP:
                match = parser.OFPMatch(eth_type=eth_type)
            elif eth_type == ETH_TYPE_IPV6:
                match = parser.OFPMatch(in_port=in_port, eth_type=eth_type, eth_src=eth_src, eth_dst=eth_dst)
            elif eth_type == ETH_TYPE_MPLS:
                match = parser.OFPMatch(in_port=in_port, eth_type=eth_type, eth_src=eth_src, eth_dst=eth_dst)
        else:
            logging.info("Set OFPMatch eth_type parameter")

        # Add entry to flow table
        if match is not None:
            flow_match.add_flow(datapath, priority, match, actions, idle_timeout)
        else:
            logging.info("No matching rule found or added")


class FlowAdd:
    '''
    Default function for constructing flow instructions
    Sends constructed message to connected switch
    '''

    def __init__(self):
        logging.info("")

    def add_flow(self, datapath, priority, match, actions, idle_timeout=1800):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)


class SendPacket:
    def __init__(self):
        logging.info("SDN controller is configured")

    def send(self, datapath, msg, port, action):
        data = None
        parser = datapath.ofproto_parser
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=port, actions=action, data=data)
        datapath.send_msg(out)


class TrackConnection:
    '''
    Firewall Connection Tracking
    Add detected flows to dictionary and track them for incoming packets
    '''

    def __init__(self):
        logging.info("Connection tracking")

    def conn_track_dict(self, dic, s_ip, d_ip, s_port, d_port, act, var):
        flag = 0
        mydict = dic
        if var == 2:
            mydict = self.conn_track_dict(mydict, d_ip, s_ip, d_port, s_port, act, 1)
        src_ip = str(s_ip)
        list1 = [d_ip, s_port, d_port, act]
        listobj = []
        # Add new flow entries
        if mydict.has_key(src_ip) is False:
            key = src_ip
            tup = tuple(list1)
            listobj.append(tup)
            tup = tuple(listobj)
            mydict[key] = tup
            flag = 1

        # Check if an entry already exists
        elif mydict.has_key(src_ip) is True:
            for x in list(mydict[src_ip]):
                if list1 == list(x):
                    flag = 1
                    break

        # Allow ff unique entry found
        if flag != 1:
            key = src_ip
            dst = mydict[key]
            dst = list(dst)
            dst.append(tuple(list1))
            tup = tuple(dst)
            mydict[key] = tup

        return mydict

