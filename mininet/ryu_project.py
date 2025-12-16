from ryu.app import simple_switch_stp_13
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import stplib

IDLE_TIMEOUT: int = 30


class STP_Switch(simple_switch_stp_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(STP_Switch, self).__init__(*args, **kwargs)
        self.datapaths = {}

    def is_voip_packet(self, pkt):
        VOIP_PORTS = {
            5060,
            5061,  # SIP
            4569,  # IAX
            1720,  # H.323
            2427,
            2727,  # MGCP
        }
        RTP_PORT_RANGE = (10000, 20000)

        udp_pkt = pkt.get_protocol(udp.udp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if udp_pkt:
            src, dst = udp_pkt.src_port, udp_pkt.dst_port

            if src in VOIP_PORTS or dst in VOIP_PORTS:
                return True

            if (
                RTP_PORT_RANGE[0] <= src <= RTP_PORT_RANGE[1]
                or RTP_PORT_RANGE[0] <= dst <= RTP_PORT_RANGE[1]
            ):
                return True

        if tcp_pkt:
            src, dst = tcp_pkt.src_port, tcp_pkt.dst_port
            if src in VOIP_PORTS or dst in VOIP_PORTS:
                return True

        return False

    def install_voip_path(self, pkt, src_mac, dst_mac):
        """Install VoIP flows on optimal path: s1 -> s3 -> s2"""

        # Get switch datapaths from stored dictionary
        s1_dp = self.datapaths.get(1)
        s3_dp = self.datapaths.get(3)
        s2_dp = self.datapaths.get(2)

        if not all([s1_dp, s3_dp, s2_dp]):
            self.logger.warning("Cannot install VoIP path: switches not ready yet")
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)

        if not (ip_pkt and udp_pkt):
            return

        priority = 100

        # S1: Forward to s3 (port 2)
        match = s1_dp.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst,
            ip_proto=17,
            udp_src=udp_pkt.src_port,
            udp_dst=udp_pkt.dst_port,
        )
        actions = [s1_dp.ofproto_parser.OFPActionOutput(2)]
        self.add_flow(s1_dp, priority, match, actions)

        # S3: Forward to s2 (port 2)
        match = s3_dp.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst,
            ip_proto=17,
            udp_src=udp_pkt.src_port,
            udp_dst=udp_pkt.dst_port,
        )
        actions = [s3_dp.ofproto_parser.OFPActionOutput(2)]
        self.add_flow(s3_dp, priority, match, actions)

        # S2: Forward to h2 (port 2)
        match = s2_dp.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst,
            ip_proto=17,
            udp_src=udp_pkt.src_port,
            udp_dst=udp_pkt.dst_port,
        )
        actions = [s2_dp.ofproto_parser.OFPActionOutput(2)]
        self.add_flow(s2_dp, priority, match, actions)

        # REVERSE PATH
        match = s2_dp.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_pkt.dst,
            ipv4_dst=ip_pkt.src,
            ip_proto=17,
            udp_src=udp_pkt.dst_port,
            udp_dst=udp_pkt.src_port,
        )
        actions = [s2_dp.ofproto_parser.OFPActionOutput(1)]
        self.add_flow(s2_dp, priority, match, actions)

        match = s3_dp.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_pkt.dst,
            ipv4_dst=ip_pkt.src,
            ip_proto=17,
            udp_src=udp_pkt.dst_port,
            udp_dst=udp_pkt.src_port,
        )
        actions = [s3_dp.ofproto_parser.OFPActionOutput(1)]
        self.add_flow(s3_dp, priority, match, actions)

        match = s1_dp.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_pkt.dst,
            ipv4_dst=ip_pkt.src,
            ip_proto=17,
            udp_src=udp_pkt.dst_port,
            udp_dst=udp_pkt.src_port,
        )
        actions = [s1_dp.ofproto_parser.OFPActionOutput(1)]
        self.add_flow(s1_dp, priority, match, actions)

        self.logger.info("VoIP path installed: s1->s3->s2")

    def block_nonvoip_on_optimal_path(self):
        """Block non-VoIP traffic from using optimal path s1->s3->s2"""

        s1_dp = self.datapaths.get(1)
        s3_dp = self.datapaths.get(3)
        s2_dp = self.datapaths.get(2)

        if not all([s1_dp, s3_dp, s2_dp]):
            return

        priority = 50  # Higher than normal (1) but lower than VoIP (100)

        # S1: Redirect non-VoIP traffic to s4 (port 3) instead of s3 (port 2)
        match = s1_dp.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=17,  # UDP only (but not VoIP ports due to lower priority)
        )
        actions = [s1_dp.ofproto_parser.OFPActionOutput(3)]  # Use s4 path
        self.add_flow(s1_dp, priority, match, actions)

        # Also block TCP traffic from optimal path on S1
        match = s1_dp.ofproto_parser.OFPMatch(eth_type=0x0800, ip_proto=6)  # TCP
        actions = [s1_dp.ofproto_parser.OFPActionOutput(3)]  # Use s4 path
        self.add_flow(s1_dp, priority, match, actions)

        self.logger.info("Non-VoIP traffic blocked from optimal path s1->s3->s2")

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        dpid = datapath.id

        # Store datapath
        self.datapaths[dpid] = datapath

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC address
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port

        # Check for VoIP and install optimal path
        if self.is_voip_packet(pkt):
            self.logger.info("VoIP detected! Installing optimal path")
            self.install_voip_path(pkt, src, dst)
            self.block_nonvoip_on_optimal_path()

            # Send this packet out via flood (VoIP flows are now installed for future packets)
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data,
            )
            datapath.send_msg(out)
            return

        # Normal traffic handling
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow for non-VoIP traffic
        if out_port != ofproto.OFPP_FLOOD:
            match_fields = {"in_port": in_port, "eth_dst": dst, "eth_src": src}

            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                match_fields["eth_type"] = 0x0800
                match_fields["ipv4_src"] = ip_pkt.src
                match_fields["ipv4_dst"] = ip_pkt.dst
                match_fields["ip_proto"] = ip_pkt.proto

                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    match_fields["tcp_src"] = tcp_pkt.src_port
                    match_fields["tcp_dst"] = tcp_pkt.dst_port

                udp_pkt = pkt.get_protocol(udp.udp)
                if udp_pkt:
                    match_fields["udp_src"] = udp_pkt.src_port
                    match_fields["udp_dst"] = udp_pkt.dst_port

            match = parser.OFPMatch(**match_fields)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            return

        # Flood packet
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
