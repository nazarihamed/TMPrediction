
from operator import attrgetter

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import arp, ethernet, ipv4, ipv6, ether_types, icmp

from ryu.lib import dpid as dpid_lib

import json,ast


import time
import copy
import numpy as np
from datetime import datetime
import csv
import os

import network_discovery

import setting

#Number of Nodes in the network for creating the Traffic Matrix
#TODO needs to be imported from file

# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base.app_manager import lookup_service_brick

from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import arp, ethernet, ipv4, ipv6, ether_types, icmp
from ryu.lib.packet import ether_types

from ryu.lib import dpid as dpid_lib
from ryu.app import simple_switch_13

class Routing(simple_switch_13.SimpleSwitch13):
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    _CONTEXTS = {"discovery": network_discovery.NetworkDiscovery}

    def __init__(self, *args, **kwargs):
        super(Routing, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        self.name = "routing"

        self.datapaths = {}

        self.discovery = lookup_service_brick('discovery')

        self.installed_paths = {}

        self.show_thred = hub.spawn_after(setting.DISCOVERY_PERIOD,self.show)

        self.exec_flag = False



    def show(self):
        while True:
            # for dp in self.datapaths.values():
            #     print(f'switch: {dp.id}\n')

            if len(self.datapaths.keys()) == setting.NUMBER_OF_NODES and self.exec_flag==False:
                self.flow_install_monitor()
                self.exec_flag = True
            hub.sleep(1)
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug(f'register datapath: {datapath.id:016x}')
                # print(f'register datapath: {datapath.id:016x}')
                self.datapaths[datapath.id] = datapath


        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug(f'unregister datapath: {datapath.id:016x}')
                # print(f'unregister datapath: {datapath.id:016x}')
                del self.datapaths[datapath.id]
            
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
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        
        self.logger.debug("[Network Routing Ok]")
        
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]

        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP: # or eth_pkt.ethertype == 35020:
            # ignore lldp packet
            return

        else:
            dst_mac = eth_pkt.dst
            src_mac = eth_pkt.src

            src_ip,dst_ip="", ""

            if arp_pkt:
                src_ip = arp_pkt.src_ip
                dst_ip = arp_pkt.dst_ip
            elif ipv4_pkt:
                src_ip = ipv4_pkt.src
                dst_ip = ipv4_pkt.dst

            
            dpid = format(datapath.id, "d").zfill(16)
            self.mac_to_port.setdefault(dpid, {})

            self.logger.debug("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)
            # self.logger.debug("packet in %s %s %s %s", dpid, src_ip, dst_ip, in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src_mac] = in_port

            # Here I have to add an SPF path from src to dst then add flow entries to all switches as follows 
            
            if src_ip=="" or dst_ip =="":
                return
            


            src_sw=datapath.id
            dst_sw=self.Ip_to_dpid(dst_ip)

            fields = (src_ip, dst_ip)
            
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            # Chetor masire raft va bargasht ro extract konim

            # self.forwarding(datapath.id, fields, src_sw, dst_sw, msg.buffer_id, data)


            # path=self.discovery.get_shortest_path(src,dst)   
        
            # print(f"shortest path between {src} and {dst} is {path}")

            # next=path[path.index(dpid)+1]
            # out_port=self.net[dpid][next]['port']

            # if dst_mac in self.mac_to_port[dpid]:
            #     out_port = self.mac_to_port[dpid][dst_mac]
            # else:
            #     out_port = ofproto.OFPP_FLOOD

            # actions = [parser.OFPActionOutput(out_port)]

            # # install a flow to avoid packet_in next time
            # if out_port != ofproto.OFPP_FLOOD:
            #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac,
            #                             ipv4_dst=dst_ip, ipv4_src=src_ip, eth_type=eth_pkt.ethertype)
            #     # match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            #     # match = parser.OFPMatch(in_port=in_port, ipv4_dst=dst_ip, ipv4_src=src_ip)
            #     # verify if we have a valid buffer_id, if yes avoid to send both
            #     # flow_mod & packet_out
                
            #     self.logger.debug("match %s", match)
                
                
            #     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            #         self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            #         return
            #     else:
            #         self.add_flow(datapath, 1, match, actions)
            # data = None
            # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            #     data = msg.data

            # out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
            #                         in_port=in_port, actions=actions, data=data)
            # datapath.send_msg(out)


    def Ip_to_dpid(self, ip):
        return int(ip.split('.')[3])
    
    def test_output(self,title = '',input=None):
        print('DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD')
        print(f'{title}\n')
        print(f'{input}\n')
        print('DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD')

    #---------------------FLOW INSTALLATION MODULE FUNCTIONS ----------------------------
    def flow_install_monitor(self): 
        print("[Flow Installation Ok]")
        out_time= time.time()
        for dp in self.datapaths.values():   
            for dp2 in self.datapaths.values():
                if dp.id != dp2.id:
                    ip_src = '10.0.0.'+str(dp.id) #=1 
                    ip_dst = '10.0.0.'+str(dp2.id)
                    fields = (ip_src, ip_dst)
                    self.forwarding(dp.id, fields, dp.id, dp2.id)
                    time.sleep(0.0005)
        end_out_time = time.time()
        out_total_ = end_out_time - out_time
        print("Flow installation ends in: {0}s".format(out_total_))
        return 
    
    # def forwarding(self, dpid, fields, src_sw, dst_sw, buffer_id, data):
    def forwarding(self, dpid, fields, src_sw, dst_sw):
        """
            Get paths and install them into datapaths.
        """
        
        self.installed_paths.setdefault(dpid, {})

        # IN DRL project the path need to be extracted using get_path() here not in discovery
        path=self.discovery.get_shortest_path(str(src_sw), str(dst_sw))

        self.installed_paths[src_sw][dst_sw] = path 
        
        ip_src=fields[0]
        ip_dst=fields[1]

        print("[PATH]{0}<-->{1}: {2}".format(ip_src, ip_dst, path))
        
        flow_info = (ip_src, ip_dst)
        
        # flow_info = (in_port, eth_type, ip_src, ip_dst, mac_src, mac_dst)

        # install flow entries to datapath along the path
        # self.install_flow(self.datapaths, self.discovery.link_to_port, path, flow_info, buffer_id, data)
        self.install_flow(self.datapaths, self.discovery.link_to_port, path, flow_info)

    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of link, so that controller can install flow entry.
            link_to_port = {(src_dpid,dst_dpid):(src_port,dst_port),}
        """
        # self.test_output("link_to_port",link_to_port)
        # self.test_output("link_to_port[(src_dpid, dst_dpid)]",link_to_port[(src_dpid, dst_dpid)])
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("Link from dpid:%s to dpid:%s is not in links" %(src_dpid, dst_dpid))
            return None 

    # def install_flow(self, datapaths, link_to_port, path,flow_info, buffer_id, data=None):
    def install_flow(self, datapaths, link_to_port, path,flow_info, data=None):
        init_time_install = time.time()
        ''' 
            Install flow entires. 
            path=[dpid1, dpid2...]
            flow_info=(src_ip, dst_ip)
        '''
        if path is None or len(path) == 0:
            self.logger.info("Path error!")
            return
        
        
        in_port = 1 # first port is access port (a host is attached to it)([n mininet first creat link between hosts and switches])
        
        first_dp = datapaths[path[0]]

        out_port = first_dp.ofproto.OFPP_LOCAL
        
        # flow entry for response from dst to host in two way connections
        back_info = (flow_info[1], flow_info[0]) 
        
        # Flow installing for middle datapaths in path
        if len(path) > 2:
            for i in range(1, len(path)-1):
                port = self.get_port_pair_from_link(link_to_port,
                                                    path[i-1], path[i])
                port_next = self.get_port_pair_from_link(link_to_port,
                                                         path[i], path[i+1])
                if port and port_next:
                    src_port, dst_port = port[1], port_next[0]
                    datapath = datapaths[path[i]]
                    self.send_flow_mod(datapath, flow_info, src_port, dst_port)
                    self.send_flow_mod(datapath, back_info, dst_port, src_port)

                    # self.send_packet_out(datapath, buffer_id, src_port,dst_port,data)
                    # self.send_packet_out(datapath, buffer_id, dst_port,src_port,data)

                    print("Inter link flow installed")
        if len(path) > 1:
            # The last flow entry
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[-2], path[-1])
            if port_pair is None:
                self.logger.info("Port is not found [len(path) > 1]")
                return
            src_port = port_pair[1]
            dst_port = 1 #I know that is the host port -- ([In mininet first creat link between hosts and switches])
            last_dp = datapaths[path[-1]]
            self.send_flow_mod(last_dp, flow_info, src_port, dst_port)
            self.send_flow_mod(last_dp, back_info, dst_port, src_port)

            # self.send_packet_out(datapath, buffer_id, src_port,dst_port,data)
            # self.send_packet_out(datapath, buffer_id, dst_port,src_port,data)

            # The first flow entry
            port_pair = self.get_port_pair_from_link(link_to_port, path[0], path[1])
            if port_pair is None:
                self.logger.info("Port not found in first hop. [len(path) > 1]")
                return
            out_port = port_pair[0]
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)

            # self.send_packet_out(datapath, buffer_id, in_port,out_port,data)
            # self.send_packet_out(datapath, buffer_id, out_port,in_port,data)

        # src and dst on the same datapath
        else:
            out_port = 1
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)

            # self.send_packet_out(datapath, buffer_id, in_port,out_port,data)
            # self.send_packet_out(datapath, buffer_id, out_port,in_port,data)

        end_time_install = time.time()
        total_install = end_time_install - init_time_install
        print("Time install", total_install)
    
    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        """
            Build flow entry, and send it to datapath.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,  
                                ipv4_src=flow_info[0], ipv4_dst=flow_info[1])

        self.add_flow(datapath, 1, match, actions)

    def add_flow(self, dp, priority, match, actions,buffer_id=None):
        """
            Send a flow entry to datapath.
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=dp,buffer_id=buffer_id, command=dp.ofproto.OFPFC_ADD, 
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=dp, command=dp.ofproto.OFPFC_ADD, 
                                    priority=priority, match=match, instructions=inst)
            
        dp.send_msg(mod)

    def del_flow(self, datapath, flow_info):
        """
            Deletes a flow entry of the datapath.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(in_port=flow_info[0], eth_type=flow_info[1],  
                                ipv4_src=flow_info[2], ipv4_dst=flow_info[3],
                                eth_src=flow_info[4], eth_dst=flow_info[5])
        mod = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0,command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out to DPID.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        
        datapath.send_msg(out)

    def build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def arp_forwarding(self, msg, src_ip, dst_ip):
        """
            Send ARP packet to the destination host if the dst host record
            is existed.
            result = (datapath, port) of host
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto

        result = self.discovery.get_host_location(dst_ip)
        if result:
            # Host has been recorded in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self.build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
            self.logger.debug("Deliver ARP packet to knew host")
        else:
            # self.flood(msg)
            pass

