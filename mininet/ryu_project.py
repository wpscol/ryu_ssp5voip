from ryu.app import simple_switch_stp_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import stplib


class STP_Switch(simple_switch_stp_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(STP_Switch, self).__init__(*args, **kwargs)

    # We must override the handler to add Layer 4 (Port) matching logic
    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn the MAC address
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port

        # Determine output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # --- MODIFICATION START: Install Flow with L4 Matching ---
        if out_port != ofproto.OFPP_FLOOD:

            # 1. Base Match (Layer 2)
            match_fields = {"in_port": in_port, "eth_dst": dst, "eth_src": src}

            # 2. Add Layer 3 (IP) and Layer 4 (TCP/UDP) specific matches
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                match_fields["eth_type"] = 0x0800  # IPv4
                match_fields["ipv4_src"] = ip_pkt.src
                match_fields["ipv4_dst"] = ip_pkt.dst
                match_fields["ip_proto"] = ip_pkt.proto

                # Check for TCP
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    match_fields["tcp_src"] = tcp_pkt.src_port
                    match_fields["tcp_dst"] = tcp_pkt.dst_port

                # Check for UDP
                udp_pkt = pkt.get_protocol(udp.udp)
                if udp_pkt:
                    match_fields["udp_src"] = udp_pkt.src_port
                    match_fields["udp_dst"] = udp_pkt.dst_port

            # 3. Create the Match object and add flow
            match = parser.OFPMatch(**match_fields)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            return
        # --- MODIFICATION END ---

        # If we didn't install a flow (flood), simply send the packet out
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
