# Luke Hall B425724 - Part C / MSc Project
# PortStats Controller - Controller that gets usage stats from switch during operation

# Stock imports
from threading import Timer

# Ryu imports
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.ofproto import ofproto_v1_3, ofproto_v1_5
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu import utils

# ML imports
import pickle
import numpy as np
from sklearn.cluster import KMeans


class PortStatsController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PortStatsController, self).__init__(*args, **kwargs)
        
        # Ryu variables & members
        self.switch_port = 4294967294   # Port number for the switch
        self.port_list = {}             # Dictionary containing port info: {port_number, hw_addr}
        self.mac_to_port = {}           # List for MAC addresses to switch port
        self.switch_responded = True    # Boolean to check whether switch has responded with port stats
        self.datapath_store = None      # Variable to store datapath so it can be used out of context
        self.dpid_store = None          # Variable to store datapath id 
        self.initial_request = True     # Boolean so requests are only sent when timer ends & on first packet_in

        # Physical network variables & members
        self.zodiac_hw_addr = '70:B3:D5:6C:DD:BB'  # MAC addr of Zodiac FX

        # DDoS detection variables & members
        self.switch_ports = []          # List of ports on switch
        self.prev_port_tx = {}          # Dictionary containing previous: {port_number, tx_packets}
        self.curr_port_tx = {}          # Dictionary containing new: {port_number, tx_packets}
        self.diff_port_tx = {}          # Dictionary containing tx difference: {port_number, difference}
        self.pktps = {}                 # Dictionary containing pkts/s: {port_number, pkts/s}
        self.pktps_ts = {}              # Dictionary containing pkts/s time-series: {port_number, [pkt/s]}
        self.ts_length = 10             # Maximum length of pkts/s time-series
        self.tx_packet_threshold = 500  # Threshold for received packets/second on port
        self.timer_length = 15          # Timer length
        self.ddos = {}                  # DDoS dictionary for each port: {port_number, flag}
        
        # Clustering variables & members
        self.model = None                             # ML model
        self.model_file = './cluster_model.mod'       # Model filename/path
        self.model_loaded = False                     # Model loaded from file flag
        self.n_clusters = 2                           # Number of clusters
        self.iters = 300                              # Number of iterations
        self.dataset = []                             # Training dataset
        self.dataset_file = 'data.txt'                # Dataset file
        
        # Init method calls
        self.__load_model()
        if len(self.dataset) > 1:
            self.model.fit(self.dataset)
            self.logger.info("ML :: Model trained")

    """ Event Handlers """

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Switch added to the controller, add table-miss entry
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
        
        """ Request port description """
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

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
            self.send_port_stats_request()
            self.initial_request = False

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """
        Handler for port description reply
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPPortDescStatsReply
        :param ev: Event message
        :return: None
        """
        self.logger.info("PortDesc :: Message received")
        for port in ev.msg.body:
            self.port_list[port.port_no] = port.hw_addr
            # Create numpy array
            self.pktps_ts[port.port_no] = np.zeros((self.ts_length))
            # Reshape array to fit ML algorithm
            # np.reshape(self.pktps_ts[port.port_no], (-1, 1))
            
            self.logger.info("PortDesc :: port_no = %d  hw_addr = %s", port.port_no, port.hw_addr)

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
                         'rx_dropped=%d tx_dropped=%d '
                         'duration_sec=%d duration_nsec=%d' %
                         (stat.port_no,
                          stat.rx_packets, stat.tx_packets,
                          stat.rx_bytes, stat.tx_bytes,
                          stat.rx_dropped, stat.tx_dropped,
                          stat.duration_sec, stat.duration_nsec))
            port_packet_recv[stat.port_no] = stat.tx_packets
        self.__ddos_detection(port_packet_recv)
        for port in ports:
            self.logger.debug('PortStats :: %s\n'
                              '----------------------------------------------------------', port)
        request_timer = Timer(self.timer_length, self.send_port_stats_request)
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
                         
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Handler for flow stats reply
        https://ryu.readthedocs.io/en/latest/ofproto_v1_5_ref.html#ryu.ofproto.ofproto_v1_5_parser.OFPFlowStatsReply
        :param ev: Event message
        :return: None
        """
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                     'duration_sec=%d duration_nsec=%d '
                     'priority=%d '
                     'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                     'cookie=%d packet_count=%d byte_count=%d '
                     'match=%s instructions=%s' %
                     (stat.table_id,
                      stat.duration_sec, stat.duration_nsec,
                      stat.priority,
                      stat.idle_timeout, stat.hard_timeout, stat.flags,
                      stat.cookie, stat.packet_count, stat.byte_count,
                      stat.match, stat.instructions))
        for flow in flows:
            self.logger.info('FlowStats :: %s\n'
                              '----------------------------------------------------------', flow)

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
            self.logger.info("PortStats :: Request Message Sent")
            # self.send_flow_stats_request()
            self.switch_responded = False
            
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
           match = ofp_parser.OFPMatch(in_port=1)
           req = ofp_parser.OFPFlowStatsRequest(self.datapath_store, 0,
                                                ofp.OFPTT_ALL,
                                                ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                cookie, cookie_mask,
                                                match)
           self.datapath_store.send_msg(req)
           self.logger.info("FlowStats :: Request Message Sent")
           self.switch_responded = False

    """ Private Methods """

    def __ddos_detection(self, new_curr):
        """
        Update current port tx
        Check whether DDoS has been detected in system
        Update previous port tx
        :return: None
        """
        self.__update_curr_tx(new_curr)
        if self.prev_port_tx:
            # self.prev_port_tx is not empty
            self.logger.debug("self.prev_port_tx not empty")
            self.__find_pkt_count_diff()
            self.__calc_pkts_per_sec()
            self.__compare_threshold()
            
            # TIME-SERIES
            for port, pktps in self.pktps.items():
                self.logger.info("ML :: Updating port %d", port)
                self.pktps_ts[port] = np.insert(self.pktps_ts[port], 0, pktps)
            
            self.logger.info("ML :: Time-series updated")
            # CLUSTERING
            for (ts_port, ts), (ddos_port, flag) in zip(self.pktps_ts.items(), self.ddos.items()):
                if ts_port == self.switch_port:
                    continue
                # print(ts.shape)
                self.logger.debug("ts port : %d", ts_port)
                self.logger.debug("dd port : %d", ddos_port)
                # Remove old value
                diff = len(ts) - 10
                ts = ts[:-diff]
                self.logger.debug("sliced :: %s", str(ts))
                
                # TRAINING
                self.dataset.append(ts)
                self.logger.debug("ML :: Dataset length: %d", len(self.dataset))
                
                # PREDICTION
                prediction = self.model.predict(ts.reshape(1,-1))
                self.logger.info("ML :: Prediction : %s", str(prediction))
                self.ddos[ts_port] = prediction
                        
            for port, flag in self.ddos.items():
                if port == self.switch_port:
                    continue
                self.logger.info("%s :: %s", str(port), str(flag))
                if flag:
                    self.logger.info("==========================================================")
                    self.logger.info("          Attack detected :: Origin =  port %d", port)
                    self.logger.info("==========================================================")
                    self.__mitigate_attack(port)
        else:
            self.logger.debug("self.prev_port_tx is empty")
        self.__update_prev_tx(self.curr_port_tx)
        self.logger.debug("Attack detection finished")
        self.__save_model()

    def __update_curr_tx(self, new_curr):
        """
        Update curr_port_tx dictionary with new values
        :param new_curr: Dictionary containing: {port_no, tx_packet_count}
        :return: None
        """
        for port, tx_count in new_curr.items():
            if port in self.curr_port_tx.keys():
                self.logger.debug("Updated curr_port: %d", port)
            else:
                self.logger.debug("New curr_port: %d", port)
            self.curr_port_tx[port] = tx_count

    def __update_prev_tx(self, new_prev):
        """
        Update prev_port_tx dictionary with new values
        :param new_prev: Dictionary containing: {port_no, tx_packet_count}
        :return: None
        """
        for port, tx_count in new_prev.items():
            if port in self.prev_port_tx.keys():
                self.logger.debug("Updated prev_port: %d", port)
            else:
                self.logger.debug("New prev_port: %d", port)
            self.prev_port_tx[port] = tx_count

    def __find_pkt_count_diff(self):
        """
        Calculates the difference in tx_packet between previous and current counts
        :return: None
        """
        for (prev_port, prev_tx), (curr_port, curr_tx) in zip(self.prev_port_tx.items(), self.curr_port_tx.items()):
            if prev_port == curr_port:
                # Port numbers match
                self.diff_port_tx[prev_port] = (curr_tx - prev_tx)
                self.logger.debug("Difference for port %d calculated", prev_port)
            else:
                self.logger.debug("Port numbers don't match")

    def __calc_pkts_per_sec(self):
        """
        Calculate packets per second for each port
        :return: None
        """
        for port, pkt_count in self.diff_port_tx.items():
            self.pktps[port] = (self.diff_port_tx[port] / self.timer_length)
            self.logger.info("Port: %d :: Pkt/s = %s", port, self.pktps[port])

    def __compare_threshold(self):
        """
        Compare pkt/s for each port to threshold, trigger DDoS flag if above
        :return: None
        """
        for port, pktps in self.pktps.items():
            if pktps >= self.tx_packet_threshold:
                self.logger.info("Port: %d :: Pkt/s >= threshold", port)
                self.ddos[port] = True
            else:
                self.logger.info("Port: %d :: Pks/s < threshold", port)
                self.ddos[port] = False

    def __mitigate_attack(self, port_no):
        """
        Enact mitigation method attacking (physical) ports
        :param port_no: source port for attacker
        :return: None
        """
        hw_addr = None

        """ Find Hardware address of port """
        for port, addr in self.port_list.items():
            if port == port_no:
                self.logger.info("PortMod :: Found MAC --> Applying mitigation")
                hw_addr = addr
        
        """ Send PortMod """
        ofp = self.datapath_store.ofproto
        ofp_parser = self.datapath_store.ofproto_parser
        
        # Bitmap of OFPPC_* flags
        config = ofp.OFPPC_PORT_DOWN

        # Mask defs found in ofproto_v1_3.py ln84
        # Bitmap of OFPPC_* flags to be changed
        mask = ofp.OFPPC_PORT_DOWN

        # Advertise defs found in ofproto_v1_3.py ln115
        advertise = (ofp.OFPPF_10MB_HD | ofp.OFPPF_100MB_FD |
                     ofp.OFPPF_1GB_FD | ofp.OFPPF_COPPER |
                     ofp.OFPPF_AUTONEG | ofp.OFPPF_PAUSE |
                     ofp.OFPPF_PAUSE_ASYM)

        req = ofp_parser.OFPPortMod(self.datapath_store, port_no,
                                    hw_addr, config,
                                    mask, advertise)
        self.datapath_store.send_msg(req)
        self.logger.info("PortMod :: Block port %d sent", port_no)

        """ Start timer to bring port back up"""
        Timer(60, self.__enable_port, args=(port_no,)).start()

    def __enable_port(self, port_no):
        """
        Handler to send another PortMod to re-enable port
        :param port_no: Port to re-enable
        :return: None
        """
        hw_addr = None

        """ Find Hardware address of port """
        for port, addr in self.port_list.items():
            if port == port_no:
                self.logger.info("PortMod :: Found MAC --> Reverting mitigation")
                hw_addr = addr
        
        """ Send PortMod """
        ofp = self.datapath_store.ofproto
        ofp_parser = self.datapath_store.ofproto_parser
        
        # This changes the port mode
        config = 0

        # Mask defs found in ofproto_v1_3.py ln84
        mask = (ofp.OFPPC_PORT_DOWN | ofp.OFPPC_NO_RECV |
                ofp.OFPPC_NO_FWD | ofp.OFPPC_NO_PACKET_IN)

        # Advertise defs found in ofproto_v1_3.py ln115
        advertise = (ofp.OFPPF_10MB_HD | ofp.OFPPF_100MB_FD |
                     ofp.OFPPF_1GB_FD | ofp.OFPPF_COPPER |
                     ofp.OFPPF_AUTONEG | ofp.OFPPF_PAUSE |
                     ofp.OFPPF_PAUSE_ASYM)
        req = ofp_parser.OFPPortMod(self.datapath_store, port_no,
                                    hw_addr, config,
                                    mask, advertise)
        self.datapath_store.send_msg(req)
        self.logger.info("PortMod :: Unblock port %d sent", port_no)
        
    def __save_model(self):
        """
        Saves clustering ML model to file
        :return: None
        """
        self.logger.info("ML :: Model saved to file")
        pickle.dump(self.model, open(self.model_file, 'wb'))
        # Save dataset
        if len(self.dataset) > 1:
            pickle.dump(self.dataset, open('data.txt', 'wb'))
        
    def __load_model(self):
        """
        Loads clustering ML model from file and sets flag accordingly
        :return: None
        """
        try:
            self.model = pickle.load(open(self.model_file, 'rb'))
            self.model_loaded = True
            self.logger.info("ML :: Model loaded from file")
            self.dataset = pickle.load(open('data.txt', 'rb'))
            self.logger.info("ML :: Dataset loaded from file")
        except IOError:
            self.model = KMeans(n_clusters=self.n_clusters, max_iter=self.iters)
            self.model_loaded = False
            self.logger.info("ML :: New model created")
            self.logger.info("ML :: No data set loaded")
