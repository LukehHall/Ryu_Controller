# Luke Hall B425724 - MSc Project
# FlowStats Controller - Controller that gets flow stats from switch during operation

from threading import Timer
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.ofproto import ofproto_v1_4
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu import utils


class FlowStatsController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(FlowStatsController, self).__init__(*args, **kwargs)
        self.port_list = {}             # Dictionary containing port info: {port_number, hw_addr}
        self.mac_to_port = {}           # List for MAC addresses to switch port
        self.switch_responded = True    # Boolean to check whether switch has responded with port stats
        self.datapath_store = None      # Variable to store datapath so it can be used out of context
        self.dpid_store = None          # Variable to store datapath id 
        self.initial_request = True     # Boolean so requests are only sent when timer ends & on first packet_in
        self.timer_length = 8
        
    """ Event Handlers """

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Switch added to the controller, add table-miss entry
        https://ryu.readthedocs.io/en/latest/ofproto_v1_5_ref.html#ryu.ofproto.ofproto_v1_5_parser.OFPSwitchFeatures
        :param ev: packet from event
        :return: None
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        """ Request port description """
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Process new/unknown flow in network, called by event triggering ( ofp_event.EventOFPPacketIn )
        https://ryu.readthedocs.io/en/latest/ofproto_v1_5_ref.html#ryu.ofproto.ofproto_v1_5_parser.OFPPacketIn
        :param ev: packet from event
        :return: None
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore LLDP packets
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.dpid_store = dpid
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet_in :: %s %s %s %s", dpid, src, dst, in_port)

        # learn mac address to avoid OFPP_FLOOD in future
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # add flow to avoid triggering EventOFPPacketIn in future
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify valid buffer_id. If valid, don't send both flow_mod & packet out
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
        # Send port stats req & update datapath
        self.datapath_store = datapath
        if self.initial_request:
            self.send_flow_stats_request()
            self.initial_request = False
            
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """
        Handler for port description reply
        https://ryu.readthedocs.io/en/latest/ofproto_v1_5_ref.html#ryu.ofproto.ofproto_v1_5_parser.OFPPortDescStatsReply
        :param ev: Event message
        :return: None
        """
        self.logger.info("PortDesc :: Message received")
        for port in ev.msg.body:
            self.port_list[port.port_no] = port.hw_addr
            self.logger.info("PortDesc :: port_no = %d  hw_addr = %s", port.port_no, port.hw_addr)
            
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Handler for flow stats reply
        https://ryu.readthedocs.io/en/latest/ofproto_v1_5_ref.html#ryu.ofproto.ofproto_v1_5_parser.OFPFlowStatsReply
        :param ev: Event message
        :return: None
        """
        self.switch_responded = True
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                     'duration_sec=%d duration_nsec=%d '
                     'priority=%d '
                     'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                     'importance=%d cookie=%d packet_count=%d '
                     'byte_count=%d match=%s instructions=%s' %
                     (stat.table_id,
                      stat.duration_sec, stat.duration_nsec,
                      stat.priority,
                      stat.idle_timeout, stat.hard_timeout,
                      stat.flags, stat.importance,
                      stat.cookie, stat.packet_count, stat.byte_count,
                      stat.match, stat.instructions))
        for flow in flows:
            self.logger.info('FlowStats :: %s\n'
                              '----------------------------------------------------------', flow)

        request_timer = Timer(self.timer_length, self.send_flow_stats_request)
        request_timer.start()
            
    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        """
        Handler for any error messages sent by switch
        :param ev: event message
        """
        msg = ev.msg
        self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
                         'message=%s',
                         msg.type, msg.code, utils.hex_array(msg.data))

    """ Public Methods"""

    @staticmethod
    def add_flow(datapath, priority, match, actions, buffer_id=None):
        """
        Add flows to switch to reduce future overhead / delay
        :param datapath: datapath of the flow
        :param priority: priority of the flow
        :param match:
        :param actions: actions to be taken
        :param buffer_id: buffer id of the flow
        :return: None
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            # replace current flow
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            # add new flow
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod) 
            
    def send_flow_stats_request(self):
        """
        Send flow stats request message to switch
        :return: None
        """
        if self.switch_responded:
            # Currently not waiting for switch to respond to previous request
            ofp = self.datapath_store.ofproto
            ofp_parser = self.datapath_store.ofproto_parser
           
            cookie = cookie_mask = 0
            for in_port in self.port_list:
                if in_port == 4294967294:
                    continue
                match = ofp_parser.OFPMatch(in_port=in_port)
                req = ofp_parser.OFPFlowStatsRequest(self.datapath_store, 0,
                                                    ofp.OFPTT_ALL,
                                                    ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                    cookie, cookie_mask,
                                                    match)
                self.datapath_store.send_msg(req)
                self.logger.info("FlowStats :: Request Message Sent [port %s]", in_port)
            self.switch_responded = False
