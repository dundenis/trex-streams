from trex_stl_lib.api import *


# x clients override the LSB of destination
#Base src ip : 55.55.1.1, dst ip: Fixed
#Increment src ipt portion starting at 55.55.1.1 for 'n' number of clients (55.55.1.1, 55.55.1.2)
#Src MAC: start with 0000.dddd.0001, increment mac in steps of 1
#Dst MAC: Fixed    (will be taken from trex_conf.yaml
#Need to switch on promiscous mode on all ports to receive all packets with different dmac
def generate_payload(length):
      word = ''
      alphabet_size = len(string.ascii_letters)
      for i in range(length):
          word += string.ascii_letters[(i % alphabet_size)]
      return word

class STLS1(object):

    def __init__ (self):
        self.num_clients  =100; # max is 16bit
        self.fsize        =1514;
        #self.min_vlan     =100
        #self.max_vlan     =199;
        self.time_sec     =300; #interval of sending garp packets //t_isg
        self.time_delay   =20; #delay of starting load - before garp sending //td_isg
        self.src_mac      ="50:6b:4b:d3:e0:bd" #source mac for garp packets of the port
        #self.num_vlans = self.max_vlan - self.min_vlan + 1
        self.dst_mac = "30:e9:8e:ff:d8:ae"; #mac-address of l3 gateway
    
    def create_stream_l2_801 (self):
        td_isg = self.time_delay * 1000000.0
        size = self.fsize - 4;
        base_pkt =  Ether(src = self.src_mac, dst = "80:00:dd:dd:00:01")/Dot1Q(vlan=80)/IP(src="10.8.0.1",dst="10.80.0.1")/UDP(dport=1025,sport=1025)
        vm = STLScVmRaw( [ STLVmFlowVar(name="mac_src", min_value=1, max_value=self.num_clients, size=2, op="inc"), # 1 byte varible, range 1-10
                           STLVmWrFlowVar(fv_name="mac_src", pkt_offset= 4),                          # write it to LSB of ethernet.src 
                           STLVmWrFlowVar(fv_name="mac_src" ,pkt_offset=36),       # it is 2 byte so there is a need to fixup in 2 bytes
                           STLVmFixIpv4(offset = "IP")
                          ],
                          cache_size=255
                        )
        pkt = STLPktBuilder(pkt=base_pkt/generate_payload(size-len(base_pkt)), vm=vm)
        return STLStream( isg = td_isg,
                          name='S_L2_VID80_InterDC_rev', 
                          packet = pkt,
                          mode = STLTXCont( pps = 10000 ),
                          flow_stats = STLFlowStats( pg_id = 81)
                          )

    def create_stream_l2_301 (self):
        td_isg = self.time_delay * 1000000.0
        size = self.fsize - 4;
        base_pkt =  Ether(src = self.src_mac, dst = "30:00:dd:dd:00:01" )/Dot1Q(vlan=30)/IP(src="10.3.0.1",dst="10.30.0.1")/UDP(dport=1025,sport=1025)
        vm = STLScVmRaw( [ STLVmFlowVar(name="mac_src", min_value=1, max_value=self.num_clients, size=2, op="inc"), # 1 byte varible, range 1-10
                           STLVmWrFlowVar(fv_name="mac_src", pkt_offset= 4),                          # write it to LSB of ethernet.src 
                           STLVmWrFlowVar(fv_name="mac_src" ,pkt_offset= 36),       # it is 2 byte so there is a need to fixup in 2 bytes
                           STLVmFixIpv4(offset = "IP")
                          ],
                          cache_size=255
                        )
        pkt = STLPktBuilder(pkt=base_pkt/generate_payload(size-len(base_pkt)), vm=vm)
        return STLStream( isg = td_isg,
                          name='S_L2_VID30_IntraDC_rev', 
                          packet = pkt,
                          mode = STLTXCont( pps = 10000 ),
                          flow_stats = STLFlowStats( pg_id = 301)
                          )

    def create_stream_l3_901 (self):
        td_isg = self.time_delay * 1000000.0
        size = self.fsize - 4;
        base_pkt =  Ether( src = self.src_mac, dst = self.dst_mac )/Dot1Q(vlan=91)/IP(src="10.91.0.1",dst="10.90.0.1")/UDP(dport=1025,sport=1025)
        vm = STLScVmRaw( [ STLVmFlowVar(name="ip_dst", min_value=1, max_value=self.num_clients, size=2, op="inc"), # 1 byte varible, range 1-10
                           STLVmWrFlowVar(fv_name="ip_dst", pkt_offset= 36),                          # write it to LSB of ethernet.src 
                           STLVmFixIpv4(offset = "IP")
                          ],
                          cache_size=255
                        )
        pkt = STLPktBuilder(pkt=base_pkt/generate_payload(size-len(base_pkt)), vm=vm)
        return STLStream( isg = td_isg,
                          name='S_L3_VID90_91_InterDC_rev', 
                          packet = pkt,
                          mode = STLTXCont( pps = 10000 ),
                          flow_stats = STLFlowStats( pg_id = 91)
                          )

    def create_garp_l3_901 (self):
        base_garp_pkt =  Ether(src = self.src_mac, dst="ff:ff:ff:ff:ff:ff")/Dot1Q(vlan=91)/ARP(psrc="10.91.0.1", hwsrc=self.src_mac, hwdst=self.src_mac, pdst="10.91.0.1")

        pkt = STLPktBuilder(pkt=base_garp_pkt)

        return STLStream( name = 'S_L3_GARP_901',
                          packet = pkt,
                          mode = STLTXSingleBurst( pps = 3, total_pkts = 3),
                          next = 'NULL_901')
                         
    def create_garp_dummy_901(self):
        t_isg = self.time_sec * 1000000.0
        return STLStream( self_start = False,
                          isg = t_isg, 
                          name = 'NULL_901',
                          mode = STLTXSingleBurst(),
                          dummy_stream = True,
                          next = 'S_L3_GARP_901')

    def create_stream_l3_701 (self):
        td_isg = self.time_delay * 1000000.0
        size = self.fsize - 4;
        base_pkt =  Ether( src = self.src_mac, dst = self.dst_mac )/Dot1Q(vlan=71)/IP(src="10.71.0.1",dst="10.70.0.1")/UDP(dport=1025,sport=1025)
        vm = STLScVmRaw( [ STLVmFlowVar(name="ip_dst", min_value=1, max_value=self.num_clients, size=2, op="inc"), # 1 byte varible, range 1-10
                           STLVmWrFlowVar(fv_name="ip_dst", pkt_offset= 36),                          # write it to LSB of ethernet.src 
                           STLVmFixIpv4(offset = "IP")
                          ],
                          cache_size=255
                        )
        pkt = STLPktBuilder(pkt=base_pkt/generate_payload(size-len(base_pkt)), vm=vm)
        return STLStream( isg = td_isg,
                          name='S_L3_VID70_71_IntraDC_rev', 
                          packet = pkt,
                          mode = STLTXCont( pps = 10000 ),
                          flow_stats = STLFlowStats( pg_id = 701)
                          )

    def create_garp_l3_701 (self):
        base_garp_pkt =  Ether(src = self.src_mac, dst="ff:ff:ff:ff:ff:ff")/Dot1Q(vlan=71)/ARP(psrc="10.71.0.1", hwsrc=self.src_mac, hwdst=self.src_mac, pdst="10.71.0.1")

        pkt = STLPktBuilder(pkt=base_garp_pkt)

        return STLStream( name = 'S_L3_GARP_701',
                          packet = pkt,
                          mode = STLTXSingleBurst( pps = 3, total_pkts = 3),
                          next = 'NULL_701')
                         
    def create_garp_dummy_701(self):
        t_isg = self.time_sec * 1000000.0
        return STLStream( self_start = False,
                          isg = t_isg, 
                          name = 'NULL_701',
                          mode = STLTXSingleBurst(),
                          dummy_stream = True,
                          next = 'S_L3_GARP_701')

    def get_streams (self, direction = 0, **kwargs):
        # create 1 stream 
        #self.streams = streams
        return [
          self.create_stream_l2_801(),
          self.create_stream_l2_301(),
          self.create_stream_l3_701(),
          self.create_stream_l3_901(),
          self.create_garp_l3_701(),
          self.create_garp_dummy_701(),
          self.create_garp_l3_901(),
          self.create_garp_dummy_901(),  
          ]
          
# dynamic load - used for trex console or simulator
def register():
    return STLS1()



