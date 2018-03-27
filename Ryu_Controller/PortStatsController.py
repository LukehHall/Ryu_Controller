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
        self.switch_responded = True    # Boolean to check whether switch has responded with port stats
        self.datapath_store = None      # Variable to store datapath so it can be used out of context
        self.initial_request = True     # Boolean so requests are only sent when timer ends & on first packet_in

        # DDoS detection variables & members
        self.switch_ports = []          # List of ports on switch
        self.prev_port_tx = {}          # Dictionary containing previous: {port_number, rx_packets}
        self.curr_port_tx = {}          # Dictionary containing new: {port_number, rx_packets}
        self.diff_port_tx = {}          # Dictionary containing rx difference: {port_number, difference}
        self.pktps = {}                 # Dictionary containing pkts/s: {port_number, pkts/s}
        self.tx_packet_threshold = 500  # Threshold for received packets on port
        self.timer_length = 60          # Timer length
        self.ddos = {}                  # DDoS dictionary for each port: {port_number, flag}

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
        if self.initial_request:
            self.send_port_stats_request()
            self.initial_request = False

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
        port_packet_recv = {}
        for stat in ev.msg.body:
            ports.append('port_no=%d '
                         'rx_packets=%d tx_packets=%d '
                         'rx_bytes=%d tx_bytes=%d '
                         'duration_sec=%d duration_nsec=%d' %
                         (stat.port_no,
                          stat.rx_packets, stat.tx_packets,
                          stat.rx_bytes, stat.tx_bytes,
                          stat.duration_sec, stat.duration_nsec))
            port_packet_recv[stat.port_no] = stat.tx_packets
            self.__ddos_detection(port_packet_recv)
        for port in ports:
            self.logger.info('PortStats: %s\n'
                             '----------------------------------------------------------', port)
        request_timer = Timer(self.timer_length, self.send_port_stats_request)
        request_timer.start()

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

    def __ddos_detection(self, new_curr):
        """
        Update current port rx
        Check whether DDoS has been detected in system
        Update previous port rx
        :return: None
        """
        self.__update_curr_tx(new_curr)
        if self.prev_port_tx:
            # self.prev_port_tx is not empty
            self.__find_pkt_count_diff()
            self.__calc_pkts_per_sec()
            self.__compare_threshold()
            for port, flag in self.ddos:
                if flag:
                    self.logger.info("DDoS detected RX on port %d", port)
        self.__update_prev_tx(self.curr_port_tx)
        self.logger.info("DDoS detection finished")

    def __update_curr_tx(self, new_curr):
        """
        Update curr_port_tx dictionary with new values
        :param new_curr: Dictionary containing: {port_no, rx_packet_count}
        :return: None
        """
        for port, rx_count in new_curr.items():
            if port in self.curr_port_tx.keys():
                self.logger.info("Updated port: %d", port)
            else:
                self.logger.info("New port: %d", port)
            self.curr_port_tx[port] = rx_count

    def __update_prev_tx(self, new_prev):
        """
        Update prev_port_tx dictionary with new values
        :param new_prev: Dictionary containing: {port_no, rx_packet_count}
        :return: None
        """
        for port,rx_count in new_prev.items():
            if port in self.prev_port_tx.keys():
                self.logger.info("Updated port: %d", port)
            else:
                self.logger.info("New port: %d", port)
            self.prev_port_tx[port] = rx_count

    def __find_pkt_count_diff(self):
        """
        Calculates the difference in rx_packet between previous and current counts
        :return: None
        """
        for prev_port, prev_tx, curr_port, curr_tx in self.prev_port_tx.items(), self.curr_port_tx.items():
            if prev_port == curr_port:
                # Port numbers match
                self.diff_port_tx[prev_port] = (curr_tx - prev_tx)
                self.logger.info("Difference for port %d calculated", prev_port)
            else:
                self.logger.info("Port numbers don't match")

    def __calc_pkts_per_sec(self):
        """
        Calculate packets per second for each port
        :return: None
        """
        for port, pkt_count in self.diff_port_tx.items():
            self.pktps[port] = (self.diff_port_tx[port] / self.timer_length)
            self.logger.info("Pkts/s for port %d = %d", port, self.pktps[port])

    def __compare_threshold(self):
        """
        Compare pkt/s for each port to threshold, trigger DDoS flag if above
        :return: None
        """
        for port, pktps in self.pktps.items():
            if pktps >= self.tx_packet_threshold:
                self.logger.info("Pkt/s >= threshold")
                self.ddos[port] = True
            else:
                self.logger.info("Pks/s < threshold")
                self.ddos[port] = False
