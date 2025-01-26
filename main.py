from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.ofproto import ofproto_v1_3

class SimpleSDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SimpleSDNController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # Stores MAC-to-port mappings
        self.packet_count_per_host = {}  # Tracks packet count per host (IP)
        self.packet_count_per_port = {}  # Tracks packet count per switch port
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handles initial connection with a switch."""
        datapath = ev.msg.datapath
        self._install_table_miss_flow(datapath)
    
    def _install_table_miss_flow(self, datapath):
        """Install a table-miss flow entry to handle unmatched packets."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Match all packets
        match = parser.OFPMatch()
        # Send unmatched packets to the controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        # Create a flow mod message
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flow_mod = parser.OFPFlowMod(
            datapath=datapath, priority=0, match=match, instructions=inst
        )
        # Send the flow mod message to the switch
        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handles packets that are sent to the controller."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Extract packet data
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # Skip processing if not an IPv4 packet
        if not ipv4_pkt:
            return

        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        # Update traffic monitoring data
        self.packet_count_per_host[src_ip] = self.packet_count_per_host.get(src_ip, 0) + 1
        self.packet_count_per_port[in_port] = self.packet_count_per_port.get(in_port, 0) + 1

        self.logger.info("Packet counts - Host: %s, Port: %s", self.packet_count_per_host, self.packet_count_per_port)

        # Check if both IPs are in the same subnet (10.0.0.0/24)
        def in_same_subnet(ip1, ip2, subnet="10.0.0.0/24"):
            subnet_ip, prefix = subnet.split('/')
            subnet_mask = (0xFFFFFFFF << (32 - int(prefix))) & 0xFFFFFFFF
            ip_to_int = lambda ip: sum(int(octet) << (8 * i) for i, octet in enumerate(reversed(ip.split('.'))))
            return (ip_to_int(ip1) & subnet_mask) == (ip_to_int(subnet_ip) & subnet_mask) and \
                   (ip_to_int(ip2) & subnet_mask) == (ip_to_int(subnet_ip) & subnet_mask)

        if in_same_subnet(src_ip, dst_ip):
            # Forward the packet
            actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
            )
            datapath.send_msg(out)
        else:
            # Drop the packet
            self.logger.info("Dropping packet from %s to %s", src_ip, dst_ip)
