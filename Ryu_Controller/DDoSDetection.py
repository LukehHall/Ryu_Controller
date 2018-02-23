# Luke Hall B425724 - Part C Project
# DDoSDetection - DDoS Detection Class

from ryu.lib.packet import packet, ethernet


class DDoSDetection:

    def __init__(self):
        super(DDoSDetection, self).__init__()
        self.ip_dict = {}           # Dictionary to hold ip addresses and number of times they have been seen
        self.packet_threshold = 10  # packets/sec threshold
        self.timer_running = False  # Boolean for timer status

    def read_packet(self, pkt):
        """
        Read the input packet to find src ip
        :param pkt: incoming packet
        :return: None
        """
        if pkt.isInstance(packet.Packet()):
            # pkt is a packet, can be used
            print("Input is a packet")
            eth = pkt.get_protocols(ethernet.ethernet[0])
            src_ip = eth.src
            self.check_ip(src_ip)
        else:
            # pkt is not a packet, return (TODO: possibly with error)
            print("Input is not a packet")
            return

    def add_new_ip(self, src_ip):
        """
        Add new IP address to dictionary (value set to 1)
        :param src_ip: New IP address to add
        :return: None
        """
        self.ip_dict[src_ip] = 1

    def check_ip(self, src_ip):
        """
        Check through dictionary for input IP, increment value if it already exists
        add IP if it doesn't already exist
        :param src_ip: input IP address
        :return: None
        """
        for ip, value in self.ip_dict.items():  # Iterate through ip_dict
            if src_ip == ip:
                # ip already exists, increment value
                value += 1
                return
        # Out of for loop, IP doesn't exist
        self.add_new_ip(src_ip)

    def reset_ip_dict(self):
        """
        Reset / Clear IP dictionary
        :return: None
        """
        self.ip_dict.clear()

    def start_timer(self):
        """
        Starts timer & sets status boolean
        :return: None
        """

    def get_timer_status(self):
        """
        Getter for whether timer running
        :return: (Boolean) timer_running
        """
        return self.timer_running
