from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import arp

from ryu.ofproto import inet

#继承ryu.base.app_manager.RyuApp
class CreateFlow(app_manager.RyuApp):
    #指定Openflow1.3版本，需要导入from ryu.ofproto import ofproto_v1_3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CreateFlow, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    #利用了一个装饰器实现了对事件的控制.这里要了解控制器事件和控制器状态。

    #控制器事件（Event)，Event具体见ryu/controller/ofp_event.py,其事件名称是由接收到的报文类型来命名的，名字为EventOFP+报文类型，
    #例如本例中，控制器收到的是交换机发送的FEATURE_REPLY报文，所以事件名称为EventOFPSwitchFeatures。
    #所以本事件其实就是当控制器接收到FEATURE_REPLY报文触发。

    #控制器状态：ryu控制器和交换机交互有4个阶段，详见ryu/ryu/controller/handler.py

    #HANDSHAKE_DISPATCHER:发送Hello报文并等待对端Hello报文。
    #CONFIG_DISPATCHER：协商版本并发送FEATURE-REQUEST报文。
    #MAIN_DISPATCHER：已收到FEATURE-REPLY报文并发送SET-CONFIG报文。
    #DEAD_DISPATCHER：与对端断开连接。

    
    #当控制器处于CONFIG_DISPATCHER状态并且接受到FEATURE_REPLY报文时，执行switch_features_handler()函数。
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)

    #函数功能：下发Table-miss流表向的过程
    def miss_table_handler(self,ev):
        #ev代表连接
        datapath = ev.msg.datapath              #从连接中获取数据平面的datapath数据结构
        ofproto = datapath.ofproto              #获取openflow协议信息
        parser = datapath.ofproto_parser        #获取协议解析

        #在连接建立成功以后，需要控制器下发一个默认流表
        #来指挥所有匹配不到交换机的数据，把他上传到控制器上

        #下发流表，使tcp协议数据包都发送到控制器进行处理
        match = parser.OFPMatch(eth_type=0x0800,ip_proto=6)                       #匹配ip,tcp协议
        #actions是动作，表示匹配成功不缓存数据包并发送给控制器。
        #OFPActionOutput将数据包发送出去,
        #第一个参数OFPP_CONTROLLER是接收端口，
        #第二个是数据包在交换机上缓存buffer_id,由于我们将数据包全部传送到控制器，所以不在交换机上缓存
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]
        self.add_miss_flow(datapath, 1, match, actions)

        #下发流表，使非tcp协议的数据包都默认处理，主要是arp协议默认处理
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]
        self.add_miss_flow(datapath, 0, match, actions)
        

    #函数功能：下发默认流表
    def add_miss_flow(self, datapath, priority, match, actions, buffer_id=None):
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #在OpenFlow1.3版本中定义了instruct指令集（交换机内部的一些操作）
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, 
                                    match=match, instructions=inst, idle_timeout=5)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, 
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
      
    #控制器在MAIN_DISPATCHER状态并且触发Packet_In事件时调用_packet_in_handler函数
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _pack_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated : only %s of %s bytes", ev.msg.msg_len,ev.msg.total_len)
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port =msg.match['in_port']
        print("in_port:",in_port)

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        iph = pkt.get_protocol(ipv4.ipv4)
        tcph = pkt.get_protocol(tcp.tcp)
        arph = pkt.get_protocol(arp.arp)

        if tcph:
            src_port = tcph.src_port
            dst_port = tcph.dst_port
            src_ip = iph.src
            dst_ip = iph.dst
            print("src_port:",src_port)
            print("dst_port:",dst_port)
            print("src_ip:",src_ip)
            print("dst_ip:",dst_ip)

            #匹配源ip
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=inet.IPPROTO_TCP,
            ipv4_src="172.21.0.2")
            if match:
                #添加请求数据包流表
                out_port = 4
                actions = [ parser.OFPActionSetField(ipv4_src="172.21.0.4"),
                            parser.OFPActionSetField(tcp_src=3333),
                            parser.OFPActionOutput(port=out_port)]
                self.add_miss_flow(datapath, 2, match, actions, msg.buffer_id)

                #添加响应数据包流表
                match_back = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=inet.IPPROTO_TCP,ipv4_dst="172.21.0.4",tcp_dst=3333)
                actions_back = [parser.OFPActionSetField(ipv4_dst=src_ip),
                                parser.OFPActionSetField(eth_dst=eth.src),
                                parser.OFPActionSetField(tcp_dst=tcph.src_port),
                                parser.OFPActionOutput(port=in_port)]
                self.add_miss_flow(datapath, 2, match_back, actions_back, msg.buffer_id)

            #向交换机发回数据
            data = None
            data = msg.data
            actions = [parser.OFPActionOutput(port=in_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            print ("PACKET_OUT...")
        else:
            print("not tcp")
            pass
