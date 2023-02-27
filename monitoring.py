
from operator import attrgetter

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3

import Routing_STP
import stplib
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import arp, ethernet, ipv4, ipv6, ether_types, icmp

from ryu.lib import dpid as dpid_lib



import time
import copy
import numpy as np
from datetime import datetime
import csv
import os



import network_discovery

import Routing_SPF

import setting

#Number of Nodes in the network for creating the Traffic Matrix
#TODO needs to be imported from file


class Monitoring(app_manager.RyuApp):
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    _CONTEXTS = {"discovery": network_discovery.NetworkDiscovery, 
                 "routing": Routing_SPF.Routing}

    def __init__(self, *args, **kwargs):
        super(Monitoring, self).__init__(*args, **kwargs)
        
        self.name='monitor'

        self.datapaths = {}

        self.discovery = kwargs["discovery"]

        self.routing = kwargs["routing"]

        # self.stp = kwargs['stplib']

        self.stats = {}
        
        self.flow_stats = {}
        
        self.flow_speed = {}
        
        self.output=setting.PATH_TO_FILES+"/log/"

        self.previous_traffic = []
        
        self.start_time = time.time()

        self.tm_flag = 0

        self.temp_bw_map_flows = {}

        self.bandwith_flow_dict = {}
        
        self.bw_flow_dict = {}

        self.latest_traffic = np.zeros((setting.NUMBER_OF_NODES, setting.NUMBER_OF_NODES), dtype=object)

        self.tm_cal_thread = hub.spawn_after(setting.MONITOR_AND_DELAYDETECTOR_BOOTSTRAP_DELAY,self._tm_cal)

              
    def test_output(self,title = '',input=None):
        print('DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD')
        print(f'{title}\n')
        print(f'{input}\n')
        print('DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD')
    
    def show_stat(self, type):
        '''
            Show statistics info according to data type.
            type: 'port' 'flow'
        '''
        bodys = self.stats[type]
        if(type == 'flow'):
            print('datapath         ''   in-port        ip-dst      '
                  'out-port packets  bytes  flow-speed(B/s)')
            print('---------------- ''  -------- ----------------- '
                  '-------- -------- -------- -----------')
            for dpid in bodys.keys():
                for stat in sorted(
                    # [flow for flow in bodys[dpid] if flow.priority == 1],
                    # key=lambda flow: (flow.match.get('in_port'),
                    #                   flow.match.get('ipv4_dst'))):
                    
                    [flow for flow in bodys[dpid] if flow.priority == 1],
                    key=lambda flow: (flow.match.get('in_port'),
                                    flow.match.get('eth_dst'))):

                    # print('=======================================')
                    # print(stat)
                    # print('=======================================')
                    print('%016x %8x %17s %8x %8d %8d %8.1f' % (
                        dpid,
                        # stat.match['in_port'], stat.match['ipv4_dst'],
                        stat.match['in_port'], stat.match['eth_dst'],
                        stat.instructions[0].actions[0].port,
                        stat.packet_count, stat.byte_count,
                        abs(self.flow_speed[dpid][
                            (stat.match.get('in_port'),
                            # stat.match.get('ipv4_dst'),
                            stat.match.get('eth_dst'),
                            stat.instructions[0].actions[0].port)][-1])))
            print('\n')

        if(type == 'port'):
            print('datapath             port   ''rx-pkts  rx-bytes rx-error '
                  'tx-pkts  tx-bytes tx-error  port-speed(B/s)'
                  ' current-capacity(Kbps)  '
                  'port-stat   link-stat')
            print('----------------   -------- ''-------- -------- -------- '
                  '-------- -------- -------- '
                  '----------------  ----------------   '
                  '   -----------    -----------')
            format = '%016x %8x %8d %8d %8d %8d %8d %8d %8.1f %16d %16s %16s'
            for dpid in bodys.keys():
                for stat in sorted(bodys[dpid], key=attrgetter('port_no')):
                    if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
                        print(format % (
                            dpid, stat.port_no,
                            stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                            stat.tx_packets, stat.tx_bytes, stat.tx_errors,
                            abs(self.port_speed[(dpid, stat.port_no)][-1]),
                            self.port_features[dpid][stat.port_no][2],
                            self.port_features[dpid][stat.port_no][0],
                            self.port_features[dpid][stat.port_no][1]))
            print('\n')

    def _tm_cal(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(0.5) # this way it will report traffic matrix each 1 sec (should be half)
            if self.tm_flag == 0:
                self.logger.debug("Calculating Traffic Matrix!")
                self.start_time = time.time()
                self.previous_traffic = copy.deepcopy(self.latest_traffic)
                self.tm_flag = 1
            else:
                duration = time.time() - self.start_time
                diff_matrix = self.latest_traffic - self.previous_traffic
                traffic_matrix = diff_matrix / max(1,int(duration)) # avoid zero in division
                if setting.TOSHOW_TM:
                    self.logger.info("Traffic Matrix: \n" + str(traffic_matrix))
                
                file_name= self.output + "log.csv"
                
                os.makedirs(os.path.dirname(file_name), exist_ok=True)
                
                if file_name is not None:
                    with open(file_name, 'a') as f:
                        f.write(datetime.now().strftime(format='%Y-%m-%d %H:%M:%S,'))
                        # f.write(datetime.now().strftime(format='%Y-%m-%d %H:%M:%S.%f,'))
                        np.savetxt(f, traffic_matrix.ravel()[None], delimiter=',', fmt = '%s')
                self.tm_flag = 0

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        # datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        
        dpid_rec = ev.msg.datapath.id
        
        traffic = np.zeros(setting.NUMBER_OF_NODES, dtype=object)

        # for statistic in ev.msg.body:
        #     # print(statistic.match)
        #     if 'in_port' in statistic.match:
        #         if ('eth_src' in statistic.match and 'eth_dst'in statistic.match and 
        #             'ipv4_src' in statistic.match and 'ipv4_dst' in statistic.match):
        #             eth_src = statistic.match['eth_src']
        #             eth_dst = statistic.match['eth_dst']
        #             ip_src = statistic.match['ipv4_src']
        #             ip_dst = statistic.match['ipv4_dst']
        #             number_bytes = statistic.byte_count
        for statistic in ev.msg.body:
            
            if ('eth_type' in statistic.match and
                'ipv4_src' in statistic.match and 'ipv4_dst' in statistic.match):
                eth_type = statistic.match['eth_type']
                ip_src = statistic.match['ipv4_src']
                ip_dst = statistic.match['ipv4_dst']
                number_bytes = statistic.byte_count

                if ip_src == "10.0.0.%d" %dpid_rec:
                    traffic[int(ip_dst.split('.')[3]) - 1] += number_bytes

                # self.logger.info("#################################")
                # self.logger.info("dpid#, traffic vector: %s, %s", dpid_rec, traffic)
                # self.logger.info("dpid#, src, dst, bytes: %s, %s, %s, %s", dpid_rec, ip_src, ip_dst, number_bytes)
                # self.logger.info("#################################")
        self.latest_traffic[int(dpid_rec)-1]=traffic


                # a='0x'+eth_src[-2:]
                # print('DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD')
                # print(ip_src)
                # print(ip_dst)
                # print(a)
                # print(number_bytes)
                # print('DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD')

                # if dpid_rec not in list(self.temp_bw_map_flows):
                #     self.temp_bw_map_flows[dpid_rec] = {}
                # if eth_src not in list(self.temp_bw_map_flows[dpid_rec]):
                #     self.temp_bw_map_flows[dpid_rec][eth_src] = {}
                # if eth_dst not in list(self.temp_bw_map_flows[dpid_rec][eth_src]):
                #     self.temp_bw_map_flows[dpid_rec][eth_src][eth_dst] = {}
                #     ts_now = (statistic.duration_sec + statistic.duration_nsec / (10 ** 9))
                #     self.temp_bw_map_flows[dpid_rec][eth_src][eth_dst]['ts'] = ts_now
                #     self.temp_bw_map_flows[dpid_rec][eth_src][eth_dst]['bytes'] = statistic.byte_count
                # # everything inside
                # else:
                #     ts_now = (statistic.duration_sec + statistic.duration_nsec / (10 ** 9))
                #     time_diff = ts_now - self.temp_bw_map_flows[dpid_rec][eth_src][eth_dst]['ts']
                #     bytes_diff = number_bytes - self.temp_bw_map_flows[dpid_rec][eth_src][eth_dst]['bytes']
                #     if time_diff > 0.0:
                #         try:
                #             bw = (bytes_diff*8) / time_diff
                #         except ZeroDivisionError:
                #             self.logger.info(
                #                 "Saved_ts: {} ts_now: {} diff: {}".format(
                #                     self.temp_bw_map_flows[dpid_rec][eth_src][eth_dst]['ts'],
                #                     ts_now, time_diff))
                        
                #         #HAMED get IP address from reverse ARP table in network_discovery module
 
                #         if dpid_rec not in list(self.bandwith_flow_dict.keys()):
                #             self.bandwith_flow_dict[dpid_rec] = {}
                #         if eth_src not in list(self.bandwith_flow_dict[dpid_rec].keys()):
                #             self.bandwith_flow_dict[dpid_rec][eth_src] = {}
                #         self.temp_bw_map_flows[dpid_rec][eth_src][eth_dst]['ts'] = ts_now
                #         self.temp_bw_map_flows[dpid_rec][eth_src][eth_dst]['bytes'] = statistic.byte_count
                #         self.bandwith_flow_dict[dpid_rec][eth_src][eth_dst] = bw

                        
                #         self.latest_traffic[int(a, base=16)]

                #         if len(self.discovery.rev_arp_table.keys())==setting.NUMBER_OF_NODES:
                #             srcIP = self.discovery.rev_arp_table[eth_src]
                #             dstIP = self.discovery.rev_arp_table[eth_dst]
                #             if srcIP not in self.bw_flow_dict.keys():
                #                 self.bw_flow_dict.setdefault(srcIP,{})
                #             if dstIP not in self.bw_flow_dict[srcIP].keys():
                #                 self.bw_flow_dict[srcIP].setdefault(dstIP,{})

                #             self.bw_flow_dict[srcIP][dstIP]=bw


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        # self.logger.info('datapath         port     '
        #                  'rx-pkts  rx-bytes rx-error '
        #                  'tx-pkts  tx-bytes tx-error')
        # self.logger.info('---------------- -------- '
        #                  '-------- -------- -------- '
        #                  '-------- -------- --------')
        # for stat in sorted(body, key=attrgetter('port_no')):
        #     self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
        #                      ev.msg.datapath.id, stat.port_no,
        #                      stat.rx_packets, stat.rx_bytes, stat.rx_errors,
        #                      stat.tx_packets, stat.tx_bytes, stat.tx_errors)
        pass

 
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug(f'register datapath: {datapath.id:016x}')
                # print(f'register datapath: {datapath.id:016x}')
                self.datapaths[datapath.id] = datapath
                #HAMED added to keep track of each flows bw consumption
                self.bandwith_flow_dict[datapath.id]={}

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug(f'unregister datapath: {datapath.id:016x}')
                # print(f'unregister datapath: {datapath.id:016x}')
                del self.datapaths[datapath.id]
                #HAMED
                del self.bandwith_flow_dict[datapath.id]
     