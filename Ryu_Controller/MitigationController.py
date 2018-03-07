# Luke Hall B425724 - Part C Project
# Mitigation Controller - Controller with attack mitigation functionality

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from Ryu_Controller.DDoSDetection import DDoSDetection


class MitigationController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3]

    def __init__(self, *args, **kwargs):
        super(MitigationController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}                       # List for MAC address to switch port
        self.detector = DDoSDetection()             # DDoS detector

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handler for switch features event, decode event packet before passing to add_flow
        :param ev: event
        :return: None
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # from ofproto_v1_3.py :
        # OFPP_CONTROLLER action = Send packet to controller
        # OFPCML_NO_BUFFER action = don't apply buffer & send whole packet to controller

        # Get IP Packet for detector
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        # Pass IP Packet to detector
        self.detector.read_packet(pkt)

        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
        Add flows to routing table for future use
        :param datapath: datapath of event packet
        :param priority: priority level of packet (0 if from switch_features, 1 if from packet_in)
        :param match:
        :param actions: actions taken by switch
        :param buffer_id: buffer id of event packet
        :return: None
        """
        # Check if DDoS detected
        self.logger.info("Checking if DDoS detected")
        if self.detector.get_ddos_detected():
            self.logger.info("DDos detected")
            # TODO: Blocking here

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # from ofproto_v1_3.py
        # OFPIT_APPLY_ACTIONS action = apply actions immediately

        # Modify a flow table entry
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        # Call DDoS detection algo here ? -- add_flow called every time a packet passes to controller
        # ( add_flow called by both packet_in & switch_features )

    def packet_in_handler(self, ev):
        """
        Decode packet with unknown flow, then send to add_flow
        :param ev: event
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

        # Pass IP Packet to detector
        self.detector.read_packet(pkt)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet_in : %s %s %s %s", dpid, src, dst, in_port)

        # Check if packet/flow has been seen before (whether it is in mac_to_port map)
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            # packet/flow is already in mac_to_port map
            # send packet to previously used port
            out_port = self.mac_to_port[dpid][dst]
        else:
            # packet/flow unknown
            # send packet to all ports
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # add flow to avoid triggering event again
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
