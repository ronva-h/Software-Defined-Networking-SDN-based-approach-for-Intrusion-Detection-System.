#opyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet,packet_base
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.ofproto import inet
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
import binascii 
import httplib2
import json
import time
import struct 
import datetime
#from scapy.all import send,IP,TCP,ICMP
import dpkt
import socket,random

from operator import attrgetter
from ryu.utils import binary_str


#from ryu.app import simple_switch_13

from ryu.controller import ofp_event

from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER

from ryu.controller.handler import set_ev_cls

from ryu.lib import hub


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        self.monitor_thread = hub.spawn(self._monitor)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
                                         
        match1 = parser.OFPMatch(in_port=3)

        actions1 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow1(datapath, 0, match, actions)
        self.add_flow2(datapath, 0, match1, actions1)


    def add_flow1(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow2(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst)
        datapath.send_msg(mod)
    


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,hard_timeout=0,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,hard_timeout=0,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        if(in_port==3): 
            #print repr(msg.data).decode('ascii')
            print struct.unpack_from('!Asdsf',buffer(msg.data),7)
            #print binascii.a2b_hex()   
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,eth_src=src, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    @set_ev_cls(ofp_event.EventOFPStateChange,

                [MAIN_DISPATCHER, DEAD_DISPATCHER])

    def _state_change_handler(self, ev):

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:

            if datapath.id not in self.datapaths:

                self.logger.debug('register datapath: %016x', datapath.id)

                self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:

            if datapath.id in self.datapaths:

                self.logger.debug('unregister datapath: %016x', datapath.id)

                del self.datapaths[datapath.id]



    def _monitor(self):

        while True:

            for dp in self.datapaths.values():

                self._request_stats(dp)

            hub.sleep(5)



    def _request_stats(self, datapath):

        self.logger.debug('send stats request: %016x', datapath.id)

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser



        req = parser.OFPFlowStatsRequest(datapath)

        datapath.send_msg(req)



        #req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)

        #datapath.send_msg(req)



    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)

    def _flow_stats_reply_handler(self, ev):

        body = ev.msg.body
        datapath=ev.msg.datapath
        self.logger.info('datapath         '

                     'in-port  eth-dst           '

                     'out-port packets  bytes')

        self.logger.info('---------------- '

                         '-------- ----------------- '

                         '-------- -------- --------')

        for stat in sorted([flow for flow in body if flow.priority == 1],

                           key=lambda flow: (flow.match['in_port'],

                                             flow.match['eth_dst'])):

            self.logger.info('%016x %8x %17s %8x %8d %8d',

                             ev.msg.datapath.id,

                             stat.match['in_port'], stat.match['eth_dst'],

                             stat.instructions[0].actions[0].port,

                             stat.packet_count, stat.byte_count)

            if stat.packet_count>0:
                self.logger.info("%8x %17s %8x %17s",stat.match['in_port'],stat.match['eth_src'],stat.instructions[0].actions[0].port,stat.match['eth_dst'])

                msg=ev.msg
                datapath = ev.msg.datapath
                ofproto=datapath.ofproto		
                parser = datapath.ofproto_parser
                #da= stat.packet_count	
                da1= stat.packet_count	
                da2=stat.match['eth_src'] 
                da3=stat.match['eth_dst']                               
                e=ethernet.ethernet(dst ='ff:ff:ff:ff:ff:ff',ethertype=0x0800)
                ipv4a = ipv4.ipv4(src='10.0.1.8',dst='10.0.1.6',proto=17)
                a=udp.udp(dst_port=5000,total_length=0,csum=0)
                p=packet.Packet()
                p.add_protocol(e)
                p.add_protocol(ipv4a)
                p.add_protocol(a)
                p.protocols.append(da1)
                p.protocols.append(",")
                p.protocols.append(da2)
                p.protocols.append(",")
                p.protocols.append(da3)
                p.serialize()
                                
                port=3
                actions=[parser.OFPActionOutput(port)]
                #actions.append();
                out=parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER,actions=actions,data = p)
                datapath.send_msg(out)


