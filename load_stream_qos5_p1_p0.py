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
        #self.fsize       =9000;
        #self.min_vlan     =100
        #self.max_vlan     =199;
        self.time_sec     =10; #interval of sending garp packets //t_isg
        #self.time_delay   =20; #delay of starting load - before garp sending //td_isg
        self.src_mac      ="00:0c:29:50:4e:8c" #source mac for garp packets of the port
        #self.num_vlans = self.max_vlan - self.min_vlan + 1
        #self.dst_mac = "f03f-95dd-185e"; #mac-address of the destination port

    def create_garp_400 (self):
        t_isg = self.time_sec * 1000000.0
        base_garp_pkt =  Ether(src=self.src_mac, dst="ff:ff:ff:ff:ff:ff")/Dot1Q(vlan=40)/ARP(psrc="10.41.0.1", hwsrc=self.src_mac, hwdst=self.src_mac, pdst="10.41.0.1")
        pkt = STLPktBuilder(pkt=base_garp_pkt)

        return STLStream( name = 'LOAD_GARP_400',
                          packet = pkt,
                          mode = STLTXSingleBurst( pps = 3, total_pkts = 3),
                          next = 'NULL_400')
                         
    def create_garp_dummy_400(self):
        t_isg = self.time_sec * 1000000.0
        return STLStream( self_start = False,
                          isg = t_isg, 
                          name = 'NULL_400',
                          mode = STLTXSingleBurst(),
                          dummy_stream = True,
                          next = 'LOAD_GARP_400')

    def get_streams (self, direction = 0, **kwargs):
        # create 1 stream 
        #self.streams = streams
        return [
          self.create_garp_400(),
          self.create_garp_dummy_400(),
          ]
          
# dynamic load - used for trex console or simulator
def register():
    return STLS1()






