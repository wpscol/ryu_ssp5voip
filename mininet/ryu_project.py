from ryu.app import simple_switch_stp_13
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.controller import ofp_event
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import stplib, hub
from ryu.ofproto import ofproto_v1_3
import time

IDLE_TIMEOUT: int = 30
VOIP_TIMEOUT: int = 10  # Remove VoIP rules after 10 seconds of no VoIP traffic


class STP_Switch(simple_switch_stp_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(STP_Switch, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.last_voip_time = None
        self.voip_active = False
        self.flows_to_migrate = []
        self.migration_in_progress = False
        self.rr_counter = 0  # Round-robin counter for load balancing

        # Start VoIP timeout monitoring thread
        self.monitor_thread = hub.spawn(self._monitor_voip_timeout)

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

    def _choose_path_round_robin(self):
        """
        Choose path for TCP flow using round-robin.
        Returns: tuple (path_name, switches_list, ports_list)

        When VoIP is NOT active: 3 paths (s3, s4, s5)
        When VoIP IS active: 2 paths (s4, s5) - s3 reserved for VoIP
        """

        if not self.voip_active:
            # Use all 3 paths
            path_id = self.rr_counter % 3

            if path_id == 0:
                # Path 1: s1→s3→s2
                return ("s3", [1, 3, 2], [(1, 2), (3, 2), (2, 2)])  # (switch, out_port)
            elif path_id == 1:
                # Path 2: s1→s4→s2
                return ("s4", [1, 4, 2], [(1, 3), (4, 2), (2, 2)])
            else:
                # Path 3: s1→s5→s6→s2
                return ("s5", [1, 5, 6, 2], [(1, 4), (5, 2), (6, 2), (2, 2)])
        else:
            # VoIP active - use only 2 alternative paths (s4, s5)
            path_id = self.rr_counter % 2

            if path_id == 0:
                # Path 1: s1→s4→s2
                return ("s4", [1, 4, 2], [(1, 3), (4, 2), (2, 2)])
            else:
                # Path 2: s1→s5→s6→s2
                return ("s5", [1, 5, 6, 2], [(1, 4), (5, 2), (6, 2), (2, 2)])

    def _install_tcp_flow_on_path(self, pkt, path_name, switches, ports):
        """
        Install TCP flow on the specified path.

        Args:
            pkt: packet object
            path_name: name of the path (for logging)
            switches: list of switch IDs in the path
            ports: list of (switch_id, out_port) tuples
        """

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if not (ip_pkt and tcp_pkt):
            return False

        priority = 1
        idle_timeout = 1  # Flows expire after 1 second of inactivity

        # Forward direction: h1 → h2
        for i, (sw_id, out_port) in enumerate(ports):
            dp = self.datapaths.get(sw_id)
            if not dp:
                self.logger.warning(f"Switch {sw_id} not available for path installation")
                continue

            ofproto = dp.ofproto
            parser = dp.ofproto_parser

            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=ip_pkt.src,
                ipv4_dst=ip_pkt.dst,
                ip_proto=6,
                tcp_src=tcp_pkt.src_port,
                tcp_dst=tcp_pkt.dst_port
            )
            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

            mod = parser.OFPFlowMod(
                datapath=dp,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=0
            )
            dp.send_msg(mod)

        # Reverse direction: h2 → h1
        # Reverse the path
        reverse_ports = list(reversed([(switches[i], ports[i-1][1] if i > 0 else 1)
                                       for i in range(len(ports))]))

        # For reverse, we need to determine input ports
        # s2→s6/s4/s3, then back to s1
        if path_name == "s3":
            # Reverse: s2(port 1)→s3(port 1)→s1(port 1)
            reverse_path = [(2, 1), (3, 1), (1, 1)]
        elif path_name == "s4":
            # Reverse: s2(port 3)→s4(port 1)→s1(port 1)
            reverse_path = [(2, 3), (4, 1), (1, 1)]
        else:  # s5
            # Reverse: s2(port 4)→s6(port 1)→s5(port 1)→s1(port 1)
            reverse_path = [(2, 4), (6, 1), (5, 1), (1, 1)]

        for sw_id, out_port in reverse_path:
            dp = self.datapaths.get(sw_id)
            if not dp:
                continue

            ofproto = dp.ofproto
            parser = dp.ofproto_parser

            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=ip_pkt.dst,
                ipv4_dst=ip_pkt.src,
                ip_proto=6,
                tcp_src=tcp_pkt.dst_port,
                tcp_dst=tcp_pkt.src_port
            )
            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

            mod = parser.OFPFlowMod(
                datapath=dp,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=0
            )
            dp.send_msg(mod)

        self.logger.info(
            f"Round-robin: Installed TCP flow {ip_pkt.src}:{tcp_pkt.src_port} → "
            f"{ip_pkt.dst}:{tcp_pkt.dst_port} on path {path_name} (counter={self.rr_counter})"
        )

        return True

    def _monitor_voip_timeout(self):
        """Background thread to monitor VoIP activity and remove rules after timeout"""
        while True:
            hub.sleep(1)  # Check every second

            if self.voip_active and self.last_voip_time:
                elapsed = time.time() - self.last_voip_time
                if elapsed > VOIP_TIMEOUT:
                    self.logger.info(
                        f"No VoIP traffic for {VOIP_TIMEOUT}s - removing VoIP rules"
                    )
                    self.remove_voip_rules()
                    self.voip_active = False
                    self.last_voip_time = None

    def remove_voip_rules(self):
        """Remove VoIP-specific flows, restore normal operation"""
        s1_dp = self.datapaths.get(1)
        s3_dp = self.datapaths.get(3)
        s2_dp = self.datapaths.get(2)

        if not all([s1_dp, s3_dp, s2_dp]):
            return

        # Delete VoIP flows (priority 100, UDP only) from s1, s3, s2
        for dp in [s1_dp, s3_dp, s2_dp]:
            ofproto = dp.ofproto
            parser = dp.ofproto_parser

            # Delete UDP VoIP flows (priority 100)
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17)  # UDP
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=100,
                match=match
            )
            dp.send_msg(mod)

        self.logger.info("VoIP rules removed - s3 path available for round-robin again")

    def migrate_tcp_flows_to_alternative_path(self):
        """Query TCP flows from s3 and migrate them to s1->s4->s2 path"""

        s3_dp = self.datapaths.get(3)

        if not s3_dp:
            self.logger.warning("Cannot migrate flows: s3 not ready yet")
            return

        # Request flow stats from s3 for TCP flows
        self.flows_to_migrate = []
        self.migration_in_progress = True

        ofproto = s3_dp.ofproto
        parser = s3_dp.ofproto_parser

        # Request TCP flows with priority 1
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6)
        req = parser.OFPFlowStatsRequest(s3_dp, 0, ofproto.OFPTT_ALL, ofproto.OFPP_ANY, ofproto.OFPG_ANY, 0, 0, match)
        s3_dp.send_msg(req)

        self.logger.info("Requested TCP flow stats from s3 for migration")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Handle flow stats reply and migrate flows to alternative path"""

        if not self.migration_in_progress:
            return

        body = ev.msg.body
        datapath = ev.msg.datapath

        # Only process replies from s3
        if datapath.id != 3:
            return

        self.logger.info(f"Received {len(body)} flow entries from s3")

        # Parse TCP flows
        for stat in body:
            # Only migrate priority 1 flows (normal traffic)
            if stat.priority != 1:
                continue

            match = stat.match
            if 'ipv4_src' in match and 'ipv4_dst' in match and 'tcp_src' in match and 'tcp_dst' in match:
                flow_info = {
                    'ipv4_src': match['ipv4_src'],
                    'ipv4_dst': match['ipv4_dst'],
                    'tcp_src': match['tcp_src'],
                    'tcp_dst': match['tcp_dst'],
                    'eth_src': match.get('eth_src'),
                    'eth_dst': match.get('eth_dst'),
                    'in_port': match.get('in_port')
                }
                self.flows_to_migrate.append(flow_info)
                self.logger.info(f"Found TCP flow to migrate: {flow_info['ipv4_src']}:{flow_info['tcp_src']} -> {flow_info['ipv4_dst']}:{flow_info['tcp_dst']}")

        # Install migrated flows on alternative path
        self._install_migrated_flows()

        # Delete old flows from optimal path
        self._delete_flows_from_optimal_path()

        self.migration_in_progress = False
        self.logger.info(f"Migration complete: {len(self.flows_to_migrate)} flows moved to s1->s4->s2 path")

    def _install_migrated_flows(self):
        """Install TCP flows on alternative path s1->s4->s2"""

        s1_dp = self.datapaths.get(1)
        s4_dp = self.datapaths.get(4)
        s2_dp = self.datapaths.get(2)

        if not all([s1_dp, s4_dp, s2_dp]):
            self.logger.warning("Cannot install migrated flows: switches not ready")
            return

        for flow in self.flows_to_migrate:
            # Forward path: h1 -> s1 -> s4 -> s2 -> h2

            # S1: Forward to s4 (port 3)
            match = s1_dp.ofproto_parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=flow['ipv4_src'],
                ipv4_dst=flow['ipv4_dst'],
                ip_proto=6,
                tcp_src=flow['tcp_src'],
                tcp_dst=flow['tcp_dst']
            )
            actions = [s1_dp.ofproto_parser.OFPActionOutput(3)]  # to s4
            self.add_flow(s1_dp, 1, match, actions)

            # S4: Forward to s2 (port 2)
            match = s4_dp.ofproto_parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=flow['ipv4_src'],
                ipv4_dst=flow['ipv4_dst'],
                ip_proto=6,
                tcp_src=flow['tcp_src'],
                tcp_dst=flow['tcp_dst']
            )
            actions = [s4_dp.ofproto_parser.OFPActionOutput(2)]  # to s2
            self.add_flow(s4_dp, 1, match, actions)

            # S2: Forward to h2 (port 2) - from s4 (port 3)
            match = s2_dp.ofproto_parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=flow['ipv4_src'],
                ipv4_dst=flow['ipv4_dst'],
                ip_proto=6,
                tcp_src=flow['tcp_src'],
                tcp_dst=flow['tcp_dst']
            )
            actions = [s2_dp.ofproto_parser.OFPActionOutput(2)]  # to h2
            self.add_flow(s2_dp, 1, match, actions)

            # Reverse path: h2 -> s2 -> s4 -> s1 -> h1

            # S2: Reverse to s4 (port 3)
            match = s2_dp.ofproto_parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=flow['ipv4_dst'],
                ipv4_dst=flow['ipv4_src'],
                ip_proto=6,
                tcp_src=flow['tcp_dst'],
                tcp_dst=flow['tcp_src']
            )
            actions = [s2_dp.ofproto_parser.OFPActionOutput(3)]  # to s4
            self.add_flow(s2_dp, 1, match, actions)

            # S4: Reverse to s1 (port 1)
            match = s4_dp.ofproto_parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=flow['ipv4_dst'],
                ipv4_dst=flow['ipv4_src'],
                ip_proto=6,
                tcp_src=flow['tcp_dst'],
                tcp_dst=flow['tcp_src']
            )
            actions = [s4_dp.ofproto_parser.OFPActionOutput(1)]  # to s1
            self.add_flow(s4_dp, 1, match, actions)

            # S1: Reverse to h1 (port 1)
            match = s1_dp.ofproto_parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=flow['ipv4_dst'],
                ipv4_dst=flow['ipv4_src'],
                ip_proto=6,
                tcp_src=flow['tcp_dst'],
                tcp_dst=flow['tcp_src']
            )
            actions = [s1_dp.ofproto_parser.OFPActionOutput(1)]  # to h1
            self.add_flow(s1_dp, 1, match, actions)

        self.logger.info(f"Installed {len(self.flows_to_migrate)} flows on alternative path s1->s4->s2")

    def _delete_flows_from_optimal_path(self):
        """Delete migrated TCP flows from optimal path switches"""

        s1_dp = self.datapaths.get(1)
        s3_dp = self.datapaths.get(3)
        s2_dp = self.datapaths.get(2)

        if not all([s1_dp, s3_dp, s2_dp]):
            return

        for flow in self.flows_to_migrate:
            # Delete from s1, s3, s2
            for dp in [s1_dp, s3_dp, s2_dp]:
                ofproto = dp.ofproto
                parser = dp.ofproto_parser

                # Forward direction
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=flow['ipv4_src'],
                    ipv4_dst=flow['ipv4_dst'],
                    ip_proto=6,
                    tcp_src=flow['tcp_src'],
                    tcp_dst=flow['tcp_dst']
                )
                mod = parser.OFPFlowMod(
                    datapath=dp,
                    command=ofproto.OFPFC_DELETE_STRICT,
                    priority=1,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match
                )
                dp.send_msg(mod)

                # Reverse direction
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=flow['ipv4_dst'],
                    ipv4_dst=flow['ipv4_src'],
                    ip_proto=6,
                    tcp_src=flow['tcp_dst'],
                    tcp_dst=flow['tcp_src']
                )
                mod = parser.OFPFlowMod(
                    datapath=dp,
                    command=ofproto.OFPFC_DELETE_STRICT,
                    priority=1,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match
                )
                dp.send_msg(mod)

        self.logger.info(f"Deleted {len(self.flows_to_migrate)} flows from optimal path (s1, s3, s2)")

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
        """Block non-VoIP traffic from using optimal path s1->s3->s2 and setup alternative path"""

        s1_dp = self.datapaths.get(1)
        s4_dp = self.datapaths.get(4)
        s2_dp = self.datapaths.get(2)

        if not all([s1_dp, s4_dp, s2_dp]):
            return

        priority = 50  # Higher than normal (1) but lower than VoIP (100)

        # S1: Redirect non-VoIP traffic to s4 (port 3) instead of s3 (port 2)
        match = s1_dp.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=17,  # UDP only (but not VoIP ports due to lower priority)
        )
        actions = [s1_dp.ofproto_parser.OFPActionOutput(3)]  # Use s4 path
        self.add_flow(s1_dp, priority, match, actions)

        # S1: Redirect TCP traffic to s4 (port 3)
        match = s1_dp.ofproto_parser.OFPMatch(eth_type=0x0800, ip_proto=6)  # TCP
        actions = [s1_dp.ofproto_parser.OFPActionOutput(3)]  # Use s4 path
        self.add_flow(s1_dp, priority, match, actions)

        # S4: Forward all TCP from s1 to s2 (catch-all for new TCP connections)
        # Forward direction (h1 -> h2)
        match = s4_dp.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,  # TCP
            in_port=1  # from s1
        )
        actions = [s4_dp.ofproto_parser.OFPActionOutput(2)]  # to s2
        self.add_flow(s4_dp, priority, match, actions)

        # Reverse direction (h2 -> h1)
        match = s4_dp.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,  # TCP
            in_port=2  # from s2
        )
        actions = [s4_dp.ofproto_parser.OFPActionOutput(1)]  # to s1
        self.add_flow(s4_dp, priority, match, actions)

        # S2: Forward TCP from s4 to h2
        match = s2_dp.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,  # TCP
            in_port=3  # from s4
        )
        actions = [s2_dp.ofproto_parser.OFPActionOutput(2)]  # to h2
        self.add_flow(s2_dp, priority, match, actions)

        # S2: Forward TCP from h2 to s4
        match = s2_dp.ofproto_parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,  # TCP
            in_port=2  # from h2
        )
        actions = [s2_dp.ofproto_parser.OFPActionOutput(3)]  # to s4
        self.add_flow(s2_dp, priority, match, actions)

        self.logger.info("Non-VoIP traffic redirected to alternative path s1->s4->s2")

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
            # Update VoIP activity timestamp
            self.last_voip_time = time.time()

            # First VoIP packet - setup optimal path
            if not self.voip_active:
                self.logger.info("VoIP detected! Installing optimal path")
                self.voip_active = True
                self.migrate_tcp_flows_to_alternative_path()
                self.install_voip_path(pkt, src, dst)
                # Note: Round-robin handles path selection, no need for catch-all blocking
            else:
                # VoIP already active - just update timestamp
                self.logger.debug("VoIP packet - updating activity timestamp")

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
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # Use round-robin for TCP flows originating from s1
        if tcp_pkt and ip_pkt and dpid == 1 and in_port == 1:  # From h1 on s1
            # Choose path using round-robin
            path_name, switches, ports = self._choose_path_round_robin()

            # Install flow on the entire chosen path
            if self._install_tcp_flow_on_path(pkt, path_name, switches, ports):
                self.rr_counter += 1  # Increment counter after successful installation

                # Send this packet via the chosen path
                out_port = ports[0][1]  # First hop output port
                actions = [parser.OFPActionOutput(out_port)]
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

        # Default behavior for non-TCP or other switches
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow for non-TCP traffic
        if out_port != ofproto.OFPP_FLOOD:
            match_fields = {"in_port": in_port, "eth_dst": dst, "eth_src": src}

            if ip_pkt:
                match_fields["eth_type"] = 0x0800
                match_fields["ipv4_src"] = ip_pkt.src
                match_fields["ipv4_dst"] = ip_pkt.dst
                match_fields["ip_proto"] = ip_pkt.proto

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
