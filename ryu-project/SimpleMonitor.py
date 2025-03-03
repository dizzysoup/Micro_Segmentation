from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import json
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

class SimpleMonitor(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x',datapath.id)
                del self.datapaths[datapath.id]
    
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
    
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x',datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    # 改為處理 PacketIn 事件以獲取實際的封包數據
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)

        # 提取以太網層
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt:
            self.logger.info("Ethernet Source: %s, Destination: %s", eth_pkt.src, eth_pkt.dst)

        # 提取 IP 層
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.logger.info("IP src: %s", ip_pkt.src)
            self.logger.info("IP dst: %s", ip_pkt.dst)
            self.logger.info("IP proto: %s", ip_pkt.proto)
            self.logger.info("IP ToS bits: 0x%02x", ip_pkt.tos)

        # 提取 TCP 層
        if ip_pkt and ip_pkt.proto == 6:  # TCP 協定
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                self.logger.info("TCP src port: %d", tcp_pkt.src_port)
                self.logger.info("TCP dst port: %d", tcp_pkt.dst_port)

        # 提取 UDP 層
        #elif ip_pkt and ip_pkt.proto == 17:  # UDP 協定
        #    udp_pkt = pkt.get_protocol(udp.udp)
        #    if udp_pkt:
        #        self.logger.info("UDP src port: %d", udp_pkt.src_port)
        #        self.logger.info("UDP dst port: %d", udp_pkt.dst_port)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        # 當收到 flow stats 回應時，這裡只處理統計信息，不再嘗試解析封包數據
        body = ev.msg.body
        for stat in body:
            self.logger.info("Flow stats: %s", stat)
