# Luke Hall B425724 - Part C Project
# DDoSDetection - DDoS Detection Class

from ryu.lib.packet import packet, ethernet
from threading import Timer


class DDoSDetection:

    def __init__(self):
        self.__ip_dict = {}           # Dictionary to hold ip addresses and number of times they have been seen
        self.__packet_threshold = 10  # Packets/sec threshold
        self.__ddos_detected = False  # Flag for whether DDoS detected
        self.__timer_running = False  # Flag for timer status
        #self.__timer = None           # Timer
        self.__timer = Timer(10, self.__timer_ended())   # 10 second interval, self.timer_ended() is handler

    def read_packet(self, pkt, src_ip):
        """
        Read the input packet to find src ip
        :param pkt: incoming packet
        :return: None
        """
        if not self.__timer_running:
            self.__reset_timer()
            self.__start_timer()
        if type(pkt) is type(packet.Packet()):
            # pkt is a packet, can be used
            self.__print_log("Input is a packet")
            #print(pkt)
            #eth = pkt.get_protocol(ethernet.ethernet[0])
            self.__print_log("Source :: " + src_ip)
            self.__check_ip(src_ip)
        else:
            # pkt is not a packet, return (TODO: possibly with error)
            self.__print_log("Input is not a packet")
            return

    def __add_new_ip(self, src_ip):
        """
        Add new IP address to dictionary (value set to 1)
        :param src_ip: New IP address to add
        :return: None
        """
        self.__ip_dict[src_ip] = 1

    def __check_ip(self, src_ip):
        """
        Check through dictionary for input IP, increment value if it already exists
        add IP if it doesn't already exist
        :param src_ip: input IP address
        :return: None
        """
        self.__print_log("Checking source IP")
        for ip, value in self.__ip_dict.items():  # Iterate through ip_dict
            if src_ip == ip:
                # ip already exists, increment value
                value += 1
                if value >= self.__packet_threshold:  # check number of packets from ip
                    self.__set_ddos_detected(True)
                return
        # Out of for loop, IP doesn't exist
        self.__add_new_ip(src_ip)

    def __reset_ip_dict(self):
        """
        Reset / Clear IP dictionary
        :return: None
        """
        self.__print_log("Reset IP dictionary")
        self.__ip_dict.clear()

    def __set_ddos_detected(self, detected):
        """
        Class private setter for ddos_detected
        :param detected: (Boolean) whether ddos_detected
        :return: None
        """
        self.__ddos_detected = detected

    def get_ddos_detected(self):
        """
        Getter for ddos_detected
        :return: (Boolean) ddos_detected
        """
        return self.__ddos_detected

    def __start_timer(self):
        """
        Starts timer & sets status boolean
        :return: None
        """
        self.__timer_running = True
        self.__timer.start()

    def __timer_ended(self):
        """
        Handler for timer ending, reset dict and timer_running
        :return: None
        """
        self.__timer = None
        self.__timer_running = False
        self.__reset_ip_dict()

    def __get_timer_status(self):
        """
        Getter for whether timer is running
        :return: (Boolean) timer_running
        """
        return self.__timer_running

    def __cancel_timer(self):
        """
        Cancel timer
        :return: None
        """
        self.__timer.cancel()

    def __reset_timer(self):
        """
        Reset timer
        :return: None
        """
        self.__print_log("Timer reset")
        self.__timer = Timer(10, self.__timer_ended())

    @staticmethod
    def __print_log(msg):
        """
        Print messages with a standard format
        :param msg: (string) message to print
        :return: None
        """
        print("DDoS :: " + msg)
