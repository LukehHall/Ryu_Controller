# Luke Hall B425724 - Part C Project
# PortStats Controller - Controller that gets usage stats from switch during operation

from threading import Timer
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER


class PortStatsController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PortStatsController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}           # List for MAC addresses to switch port
        self.switch_responded = True   # Boolean to check whether switch has responded with port stats
        self.datapath_store = None      # Variable to store datapath so it can be used out of context
        self.timer = None

    """ Event Handlers """

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Process features response message from switch, called by event trigger ( opf_event.EventOFPSwitchFeatures )
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPSwitchFeatures
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Process new/unknown flow in network, called by event triggering ( ofp_event.EventOFPPacketIn )
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPPacketIn
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
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in: %s %s %s %s", dpid, src, dst, in_port)

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
        self.send_port_stats_request()

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """
        Handler for port stats reply (docs link below)
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPPortStatsReply
        :param ev: Event message
        :return: None
        """
        self.switch_responded = True
        ports = []
        for stat in ev.msg.body:
            ports.append('port_no=%d '
                            'rx_packets=%d tx_packets=%d '
                            'rx_bytes=%d tx_bytes=%d '
                            'duration_sec=%d duration_nsec=%d' %
                            (stat.port_no,
                            stat.rx_packets, stat.tx_packets,
                            stat.rx_bytes, stat.tx_bytes,
                            stat.duration_sec, stat.duration_nsec))
        for port in ports:
            self.logger.info('PortStats: %s\n\n', port)
        #request_timer = Timer(30, self.send_port_stats_request(ev.msg.datapath))  # Timer to send new OFPPortStats
        #request_timer.start()
        request_timer = Timer(60, self.send_port_stats_request)
        request_timer.start()

    """ Public Methods"""

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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

    def send_port_stats_request(self):
        """
        Send port stats request message to switch
        :return: None
        """
        if self.switch_responded:
            # Currently not waiting for switch to respond to previous request
            ofp = self.datapath_store.ofproto
            ofp_parser = self.datapath_store.ofproto_parser

            # ofp.OFPP_ANY sends request for all ports
            req = ofp_parser.OFPPortStatsRequest(self.datapath_store, 0, ofp.OFPP_ANY)
            self.datapath_store.send_msg(req)
            self.logger.info("Port Stats Request Message Sent")
            self.switch_responded = False

    """ Private Methods """
