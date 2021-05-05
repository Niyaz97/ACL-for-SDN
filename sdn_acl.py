import array
import copy

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import MAIN_DISPATCHER,set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet,ethernet,ipv4,udp,tcp,icmp
from ryu.ofproto.ether import ETH_TYPE_IP, ETH_TYPE_ARP
from ryu.ofproto.inet import IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP
from ryu.lib import snortlib

from flow_control import SwitchInfo, SendPacket, Construct, TrackConnection


ICMP_PING = 8
ICMP_PONG = 0
TCP_SYN = 0x02
TCP_SYNACK = 0x12
TCP_FLAG = 0x15


class Firewall(app_manager.RyuApp):
    '''
    Main class of the ACL module
    Handles every event that comes from event dispatcher
    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    inner_policy = {}
    icmp_conn_track = {}
    tcp_conn_track = {}
    udp_conn_track = {}
    sendpkt = SendPacket()
    flow = Construct()
    conn_track = TrackConnection()


    def __init__(self, *args, **kwargs):
        super(Firewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        parser = ParseRules()
        self.inner_policy = parser.parse()

        self.snort = kwargs['snortlib']
        self.snort_port = 3
        socket_config = {'unixsock': True}
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    def packet_print(self, pkt):
        '''
        Logging the packet that triggers Snort alert
        '''
        pkt = packet.Packet(array.array('B', pkt))

        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)
        _tcp = pkt.get_protocol(tcp.tcp)
        _udp = pkt.get_protocol(udp.udp)

        if _icmp:
            self.logger.info("Source IP: %r, Destination IP: %r", _ipv4.src, _ipv4.dst)

        if _tcp:
            self.logger.info("Source IP and port: %r:%r, Destination IP and port: %r:%r", _ipv4.src, _tcp.src_port, _ipv4.dst, _tcp.dst_port)

        if _udp:
            self.logger.info("Source IP and port: %r:%r, Destination IP and port: %r:%r", _ipv4.src, _udp.src_port, _ipv4.dst, _udp.dst_port)


    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        '''
        Print Snort alert in logs
        '''
        msg = ev.msg
        print('alertmsg: %s' % ''.join(msg.alertmsg))
        self.packet_print(msg.pkt)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        '''
        Get information of connected switch
        '''
        SwitchInfo(ev)
    

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
        Handling incoming packets, decoding and checking for suitable rules
        '''
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        try:
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            ethtype = eth.ethertype
        
            out_port = self.port_learn(datapath, eth, in_port)
            action_fwd_to_out_port = [parser.OFPActionOutput(out_port)]
            action_drop = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
            actions_default =  action_fwd_to_out_port
    
            if(out_port != ofproto.OFPP_FLOOD) and (ethtype == ETH_TYPE_IP):
                ip_object = pkt.get_protocols(ipv4.ipv4)[0]

                if(ip_object.proto == IPPROTO_ICMP):
                    flag1 = 0
                    icmp_objectb = pkt.get_protocol(icmp.icmp)
                    
                    if (icmp_objectb.type == ICMP_PING) and self.inner_policy.has_key(ip_object.src):
                        temp = self.inner_policy.get(ip_object.src)
                        for i in range(0,len(temp)):
                            if temp[i][0] == ip_object.dst:
                                xyz = temp[i]
                                if (xyz[1] == 'ICMP') and (xyz[5] == 'ALLOW'):
                                    flag1 = 1
                                    actions_default = action_fwd_to_out_port
                                    self.icmp_conn_track = self.conn_track.conn_track_dict(self.icmp_conn_track,ip_object.src, ip_object.dst, "PING", "PONG", xyz[5], 2)
                                    self.logger.info("%s  ->  %s : ECHO REQUEST ALLOWED" % (ip_object.src,ip_object.dst))
                                    break

                    elif (icmp_objectb.type == ICMP_PONG) and (self.icmp_conn_track.has_key(ip_object.src)):
                        temp2 = self.icmp_conn_track.get(ip_object.src)
                        for i in range(0,len(temp2)): 
                            if temp2[i][0] == ip_object.dst:
                                xyz = temp2[i]
                                if ((xyz[1] == 'PONG') and (xyz[3] == 'ALLOW')):
                                    flag1 = 1
                                    actions_default = action_fwd_to_out_port
                                    self.logger.info("%s  ->  %s : ECHO REPLY ALLOWED" % (ip_object.src,ip_object.dst))
                                    self.logger.info("\n%s  ->  %s  action= %s  state= ESTABLISHED \n" % (xyz[0],ip_object.src,xyz[2]))
                                    break
                    
                    if (flag1 == 0):
                        actions_default = action_drop
                        self.logger.info("%s  ->  %s : BLOCKED" % (ip_object.src,ip_object.dst))

                elif ip_object.proto == IPPROTO_TCP:
                    tcp_object = pkt.get_protocol(tcp.tcp)
                    flag2 = 0

                    if ((tcp_object.bits & TCP_SYN) == TCP_SYN) & ((tcp_object.bits & TCP_FLAG) == 0x00):
                        if self.inner_policy.has_key(ip_object.src):
                            temp = self.inner_policy.get(ip_object.src)
                            for i in range(0,len(temp)):
                                if (temp[i][0] == ip_object.dst) and (temp[i][1] == 'TCP') and (int(temp[i][2]) == tcp_object.src_port) and (int(temp[i][3]) == tcp_object.dst_port)  and  (temp[i][5] == 'ALLOW'):
                                    flag2 = 1
                                    actions_default = action_fwd_to_out_port
                                    self.tcp_conn_track = self.conn_track.conn_track_dict(self.tcp_conn_track, ip_object.src, ip_object.dst, tcp_object.src_port, tcp_object.dst_port, tcp_object.seq, 1)
                                    self.logger.info("%s  ->  %s : SYN ALLOWED" % (ip_object.src,ip_object.dst))
                                    break
                    
                    elif (tcp_object.bits & TCP_SYNACK) == TCP_SYNACK:
                        if self.tcp_conn_track.has_key(ip_object.dst):
                            temp2 = self.tcp_conn_track.get(ip_object.dst)
                            for i in range(0,len(temp2)):
                                if (temp2[i][0] == ip_object.src) and (int(temp2[i][1]) == tcp_object.dst_port) and (int(temp2[i][2]) == tcp_object.src_port):
                                    flag2 = 1 
                                    actions_default = action_fwd_to_out_port
                                    self.tcp_conn_track = self.conn_track.conn_track_dict(self.tcp_conn_track,ip_object.src, ip_object.dst, tcp_object.src_port, tcp_object.dst_port, tcp_object.seq,1)
                                    self.logger.info("%s  ->  %s : SYN ACK ALLOWED" % (ip_object.src,ip_object.dst))
                                    self.logger.info("\n%s  ->  %s  src_port= %s  dst_port= %s  state= ESTABLISHED \n" % (ip_object.dst,ip_object.src,temp2[i][1],temp2[i][2]))
                                    break
                    
                    else:
                        if self.tcp_conn_track.has_key(ip_object.src):
                            temp3 = self.tcp_conn_track.get(ip_object.src)
                            for i in range(0,len(temp3)):
                                if ((temp3[i][0] == ip_object.dst) and (int(temp3[i][1]) == tcp_object.src_port) and (int(temp3[i][2]) == tcp_object.dst_port)):
                                    flag2 = 1
                                    actions_default = action_fwd_to_out_port
                                    self.logger.info("%s  ->  %s : TRANSMISSION ALLOWED" % (ip_object.src,ip_object.dst))
                                    break
                      
                    if flag2 == 0:
                        actions_default = action_drop
                        self.logger.info("%s  ->  %s : SYN BLOCKED" % (ip_object.src,ip_object.dst))

                elif ip_object.proto == IPPROTO_UDP:
                    flag3 = 0 
                    udp_object = pkt.get_protocol(udp.udp)
                    if self.udp_conn_track.has_key(ip_object.dst):
                        tmp_tpl = self.udp_conn_track.get(ip_object.dst)
                        tmp = list(tmp_tpl)
                        for i in range(0,len(tmp)):
                            if (tmp[i][0] == ip_object.src):
                                xyz = tmp[i]
                                if (int(xyz[1]) == udp_object.dst_port) and (int(xyz[2]) == udp_object.src_port) and (xyz[3] == 'UNREPLIED'):
                                    flag3 = 1
                                    self.logger.info("%s  ->  %s  : UDP PACKET ALLOWED" % (ip_object.src,ip_object.dst))
                                    actions_default = action_fwd_to_out_port  
                                    del tmp[i]
                                    self.logger.info("\n%s  ->  %s  src_port= %s  dst_port= %s  state= ASSURED\n" % (ip_object.src,ip_object.dst, udp_object.src_port, udp_object.dst_port))
                                    break           
                        tmp_tpl = tuple(tmp)
                        if len(tmp_tpl) != 0:
                            self.udp_conn_track[ip_object.dst] = tmp_tpl
                        else:
                            self.udp_conn_track.pop(ip_object.dst,None)
                            
                    elif self.inner_policy.has_key(ip_object.src):
                        temp = self.inner_policy.get(ip_object.src)
                        for i in range(0,len(temp)):
                            if temp[i][0] == ip_object.dst:
                                xyz = temp[i]
                                if (xyz[1] == 'UDP') and (int(xyz[2]) == udp_object.src_port) and (int(xyz[3]) == udp_object.dst_port) and (xyz[5] == 'ALLOW'):
                                    flag3 = 1
                                    actions_default = action_fwd_to_out_port  
                                    self.udp_conn_track = self.conn_track.conn_track_dict(self.udp_conn_track, ip_object.src, ip_object.dst, udp_object.src_port, udp_object.dst_port, "UNREPLIED", 1)
                                    self.logger.info("%s  ->  %s  : UDP PACKET ALLOWED" % (ip_object.src, ip_object.dst))
                                    self.logger.info("\n%s  ->  %s  src_port= %s  dst_port= %s  state= UNREPLIED\n" % (ip_object.src, ip_object.dst, udp_object.src_port, udp_object.dst_port))
                                    break
                    
                    if flag3 == 0:
                        actions_default = action_drop
                        self.logger.info("%s  ->  %s : UDP BLOCKED" % (ip_object.src, ip_object.dst))

                else:
                    self.logger.info("Wrong protocol found")
                    actions_default = action_drop

            elif ethtype == ETH_TYPE_ARP:
                self.arp_handling(datapath, out_port, eth, in_port)
                actions_default = action_fwd_to_out_port

            else: 
                actions_default = action_drop
                
        except Exception as err:
            action_drop = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
            actions_default = action_drop
            
        finally:    
            self.sendpkt.send(datapath, msg, in_port, actions_default)

    def arp_handling(self,datapath, out_port, eth_obj, in_port):
        '''
        Add ARP rules to flow table
        '''
        if out_port != datapath.ofproto.OFPP_FLOOD:
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.flow.add_flow(datapath=datapath, actions=actions, priority=1000, in_port=in_port, 
                               eth_type=ETH_TYPE_ARP, eth_src=eth_obj.src, eth_dst=eth_obj.dst)

    def port_learn(self, datapath, eth_obj, in_port):
        '''
        Learn switch port associated with a MAC-address
        '''
        try:
            self.mac_to_port.setdefault(datapath.id, {})
            self.mac_to_port[datapath.id][eth_obj.src] = in_port
            
            if (eth_obj.ethertype == ETH_TYPE_IP) or (eth_obj.ethertype == ETH_TYPE_ARP):
                    if eth_obj.dst in self.mac_to_port[datapath.id]:
                        out_port = self.mac_to_port[datapath.id][eth_obj.dst]
                    else:
                        out_port = datapath.ofproto.OFPP_FLOOD
        except Exception as err:
            self.info(err.message)
            out_port = datapath.ofproto.OFPP_FLOOD
        finally:
            return out_port


class ParseRules:
    '''
    Parsing firewall rules
    '''
    def parse(self):
        firewall_file = open("$HOME/ACL-for-SDN/rules.txt")
        list1 = []
        firewall_dict = {}
        listobj = []

        lines = [line.strip() for line in firewall_file]
        for i in range(len(lines)):

            list1.append(lines[i].split(','))
            list2 = copy.deepcopy(list1)
            if firewall_dict.has_key(str(list2[i][0])) is False:
                key = str(list2[i][0])
                list2[i].remove(key)
                tup = tuple(list2[i])
                listobj.append(tup)
                tup = tuple(listobj)
                firewall_dict[key] = tup

            elif firewall_dict.has_key(str(list2[i][0])) is True:
                key = str(list2[i][0])
                dst = firewall_dict[key]
                dst = list(dst)
                list2[i].remove(key)
                dst.append(tuple(list2[i]))
                tup = tuple(dst)
                firewall_dict[key] = tup

            del listobj[:]
        print(len(firewall_dict.keys()))

        return firewall_dict