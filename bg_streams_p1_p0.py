from trex_stl_lib.api import *


# x clients override the LSB of destination
#Base src ip : 55.55.1.1, dst ip: Fixed
#Increment src ipt portion starting at 55.55.1.1 for 'n' number of clients (55.55.1.1, 55.55.1.2)
#Src MAC: start with 0000.dddd.0001, increment mac in steps of 1
#Dst MAC: Fixed    (will be taken from trex_conf.yaml
def generate_payload(length):
      word = ''
      alphabet_size = len(string.ascii_letters)
      for i in range(length):
          word += string.ascii_letters[(i % alphabet_size)]
      return word

class STLS1(object):

    def __init__ (self):
        self.num_clients  =15000; # max is 16bit
        self.fsize        =1514;
        self.min_vlan     =100
        self.max_vlan     =199;
        self.time_sec     =600; #interval of sending garp packets
        self.time_delay   =10; #delay of starting load - before garp sending
        self.src_mac      ="00:0c:29:50:4e:8c" #source mac for garp packets of the port
        self.num_vlans = self.max_vlan - self.min_vlan + 1


    def create_bg_garp_10 (self):
        t_isg = self.time_sec * 1000000.0
        base_garp_pkt =  Ether(src=self.src_mac, dst="ff:ff:ff:ff:ff:ff")/Dot1Q(vlan=100)/ARP(psrc="58.0.0.1", hwsrc=self.src_mac, hwdst=self.src_mac, pdst="58.0.0.1")
        vm = STLScVmRaw([ STLVmFlowVar(name="vlan_id", min_value=self.min_vlan, max_value=self.max_vlan, size=2, op="inc"),
                           STLVmWrMaskFlowVar(
                            fv_name="vlan_id",
                            pkt_offset=14,
                            pkt_cast_size=2,
                            shift=0
                            )
                           ]
                       )
        pkt = STLPktBuilder(pkt=base_garp_pkt, vm=vm)
        return STLStream( name = 'BG_GARP_10',
                          packet = pkt,
                          mode = STLTXSingleBurst( pps = 400, total_pkts = self.num_vlans),
                          next = 'NULL_10')
                         
    def create_garp_dummy_10(self):
        t_isg = self.time_sec * 1000000.0
        return STLStream( self_start = False,
                          isg = t_isg, 
                          name = 'NULL_10',
                          mode = STLTXSingleBurst(),
                          dummy_stream = True,
                          next = 'BG_GARP_10')

    def get_streams (self, direction = 0, **kwargs):
        # create 1 stream 
        #self.streams = streams
        return [
          self.create_bg_garp_10(),
          self.create_garp_dummy_10(),  
          ]
          

# dynamic load - used for trex console or simulator
def register():
    return STLS1()



