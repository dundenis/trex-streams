from trex_stl_lib.api import *
import scapy.contrib.igmp

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
        self.num_groups  =100; # max is 16bit
        self.fsize       =9000;
        #self.min_vlan     =100
        #self.max_vlan     =199;
        #self.time_sec     =3; #interval of sending garp packets //t_isg
        #self.time_delay   =20; #delay of starting load - before garp sending //td_isg
        #self.src_mac      ="00:0c:29:50:4e:8c" #source mac for garp packets of the port
        #self.num_vlans = self.max_vlan - self.min_vlan + 1
        #self.dst_mac = "f03f-95dd-185e"; #mac-address of the destination port
    
    def create_stream_l2_400 (self):
        #td_isg = self.time_delay * 1000000.0
        size = self.fsize - 4;
        #generating 5tuple flows with 802.1p =5 and dscp = ef (46, tos = 184), should no be drops 
        base_pkt =  Ether()/Dot1Q(vlan=40, prio=5)/IP(src="10.40.0.1", dst = "10.40.0.1", tos=184)/UDP(sport=1025,dport=12)
        vm = STLScVmRaw( [ STLVmTupleGen( ip_min = "10.40.0.1",
                                          ip_max = "10.40.0.254",
                                          port_min = 1025,
                                          port_max = 65535,
                                          name = 'load1'), 
                           STLVmWrFlowVar(fv_name="load1.ip", pkt_offset="IP.src"), 
                           STLVmFixIpv4(offset = "IP"),
                           STLVmWrFlowVar(fv_name="load1.port", pkt_offset="UDP.sport"),
                          ],
                          #cache_size=255
                        )
        pkt = STLPktBuilder(pkt=base_pkt/generate_payload(size-len(base_pkt)), vm=vm)

        return STLStream( #isg = td_isg,
                          name='S_L2_LOAD1_VID40_COS5', 
                          packet = pkt,
                          mode = STLTXCont( pps = 1000 )
                          #flow_stats = STLFlowStats( pg_id = 100)
                        )

    def get_streams (self, direction = 0, **kwargs):
        # create 1 stream 
        #self.streams = streams
        return [
          self.create_stream_l2_400(),
          ]
          
# dynamic load - used for trex console or simulator
def register():
    return STLS1()






