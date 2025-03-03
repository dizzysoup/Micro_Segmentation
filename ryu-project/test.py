import json
import logging
from webob import Response

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib
from ryu.topology.api import get_host  # 引入拓撲 API

simple_switch_instance_name = 'simple_switch_api_app'

class SimpleSwitchRest13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchRest13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.switches = {}
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController, {simple_switch_instance_name: self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.switches[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        # 在 Swtich 與 Controller 連結時，對 Table 0（也就是封包第一個會到達的 Table）加入規則，將封包直接轉往 Controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # 設置ACL規則
        self.setup_acl_rules(datapath)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def setup_acl_rules(self, datapath):
        with open("config/dsl_rules.txt", "r") as file:
            dsl_rules = file.readlines()

        for rule in dsl_rules:
            rule = rule.strip()
            parsed_rule = self.parse_rule(rule)  # 解析每條規則
            if parsed_rule:
                self.setup_flow_for_acl(datapath, parsed_rule)

    def parse_rule(self, rule):
        # 解析 DSL 規則
        parts = rule.split(", ")
        print("===============================================")
        print(parts)
       
        # 檢查規則是否符合預期格式
        if len(parts) != 3:
            print(f"Skipping invalid rule: {rule}")
            return None  # 如果格式不對則跳過這條規則
        
        
        src_info = parts[0].strip("{}").split(", ")
        dst_info = parts[2].strip("{}").split(", ")
            
        # 解析協議和端口
            
        if(parts[1] == "*"):
                protocol = "*"
                port = "*"
        elif(parts[1] == "ICMP"):
                protocol = "ICMP"
                port = "*"
        else :
                protocol, port = parts[1].split(" ")
            

        src_ip = src_info[0].split(',')[0].split(":")[1].strip()            
        src_label =  src_info[0].split(',')[1].split(":")[1].strip()
        dst_ip = dst_info[0].split(',')[0].split(":")[1].strip()
        dst_label = dst_info[0].split(',')[1].split(":")[1].strip()
            
        return {
                "src_ip": src_ip,
                "src_label": src_label,
                "dst_ip": dst_ip,
                "dst_label": dst_label,
                "protocol": protocol,
                "port": port
        }
        
        

    def setup_flow_for_acl(self, datapath, parsed_rule):
        # 根據解析的規則設置流規則
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        src_ip = parsed_rule["src_ip"]
        dst_ip = parsed_rule["dst_ip"]
        protocol = parsed_rule["protocol"]
        port = parsed_rule["port"]

        # 根據協議創建匹配規則
        match = None
        if protocol == "TCP":
            match = self.create_tcp_match(datapath,src_ip, dst_ip, port)
        elif protocol == "UDP":
            match = self.create_udp_match(datapath,src_ip, dst_ip, port)
        elif protocol == "ICMP":
            match = self.create_icmp_match(datapath,src_ip, dst_ip)
        
        if match:
            # 生成動作（允許流量）
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            self.add_flow(datapath, 10, match, actions)

    def create_tcp_match(self,datapath, src_ip, dst_ip, port):
        parser = datapath.ofproto_parser
        return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=6)

    def create_udp_match(self,datapath, src_ip, dst_ip, port):
        parser = datapath.ofproto_parser
        return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=17)

    def create_icmp_match(self,datapath, src_ip, dst_ip):
        parser = datapath.ofproto_parser
        return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=1)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dst = eth.dst
        src = eth.src
        
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][src] = in_port

        if dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=None)
        datapath.send_msg(out)



class SimpleSwitchController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SimpleSwitchController, self).__init__(req, link, data, **config)
        self.simpl_switch_spp = data[simple_switch_instance_name]

    @route('index', '/', methods=['GET'])
    def index(self, req, **kwargs):
        try:
            with open('templates/index.html', 'r') as file:
                body = file.read()
            return Response(content_type='text/html', body=body)
        except Exception as e:
            return Response(status=500, body="Error loading index.html")

    @route('topology', '/ryu/hosts', methods=['GET'])
    def list_topology_hosts(self, req, **kwargs):
        # 從拓撲中獲取所有主機資訊
        all_hosts = get_host(self.simpl_switch_spp, None)  # 獲取所有主機
        
        # 將主機資訊轉換為 JSON 格式
        body = json.dumps([host.to_dict() for host in all_hosts])
        print(body)
        return Response(content_type='application/json; charset=utf-8', body=body)
