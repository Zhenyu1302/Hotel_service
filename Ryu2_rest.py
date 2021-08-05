import json,requests
from operator import attrgetter
from ryu.app import simple_switch_13
from webob import Response
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub, mac
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

simple_switch_instance_name = 'traffic_monitor_api_app'
url = '/blockedMAC'
urlMAC = '/blockedMAC/{MAC}'

class SimpleMonitor(simple_switch_13.SimpleSwitch13):
    traffic = {}
    _CONTEXTS = {'wsgi':WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController,{simple_switch_instance_name: self})
        
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        
    def drop_flow(self,datapath,drop_eth_dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst=drop_eth_dst)
        actions = [parser.OFPActionOutput(port=0,max_len=ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath,10,match,actions)
        
    def byte_count_reset(self,datapath,recover_eth_dst,origin_output):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst=recover_eth_dst)
        actions = [parser.OFPActionOutput(port=origin_output,max_len=ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                match=match, instructions=inst, 
                                command = ofproto.OFPFC_MODIFY,
                                flags=ofproto.OFPFF_RESET_COUNTS)
        datapath.send_msg(mod)          
   
    def traffic_control(self,datapath,drop_eth_dst,out_port,flags):
        if flags == 0:
            self.drop_flow(datapath,drop_eth_dst)
            self.traffic[drop_eth_dst] = out_port
            global dp
            dp = datapath
        elif flags == 1:
            origin_output = self.traffic[drop_eth_dst]
            self.byte_count_reset(SimpleMonitor,dp,drop_eth_dst,origin_output)            
            del self.traffic[drop_eth_dst]     
         
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
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
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)    
    

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
     
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
                             datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
            #print(self.traffic)                 
            if stat.byte_count > 2000 and stat.match['eth_dst'] not in self.traffic.keys() and str(hex(datapath.id))[-1] =='1' and int(stat.instructions[0].actions[0].port) != 3:
                self.traffic_control(datapath,stat.match['eth_dst'],stat.instructions[0].actions[0].port,0)
            else:
                continue
                
class SimpleSwitchController(ControllerBase):

    def __init__(self,req,link,data,**config):
        super(SimpleSwitchController,self).__init__(req,link,data,**config)
        self.simple_switch_app = data[simple_switch_instance_name]
        
    @route('simpleswitch', url, methods=['GET'])
    def print_blockedMAC(self, req, **kwargs):
        simple_switch = self.simple_switch_app
        body = json.dumps(SimpleMonitor.traffic)
        return Response(content_type='text/plain', body=body)
        
    @route('simpleswitch', urlMAC, methods=['PUT'],requirements={'MAC':mac.HADDR_PATTERN})
    def remove_blockedMAC(self,req,**kwargs):
        simple_switch = self.simple_switch_app
        MAC = kwargs['MAC']
        SimpleMonitor.traffic_control(SimpleMonitor,datapath=0,drop_eth_dst=MAC,out_port=0,flags=1)
        body = json.dumps(SimpleMonitor.traffic)
        return Response(content_type='text/plain', body=body)       
