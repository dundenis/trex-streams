~�&�����e����)���qrX���(���׭�����z�b��b�pZ��+r*y�u��-��b��H��ޙ����"��h�ب��Z�ا��y�u��+�{�m��}�bz{l�y�^y�vJ� +-j�p��t�Mu�t�Mb��ޙ�홧"��^���;-0 ����)em�Z��߮����\�w�jiMy�m��"��h���+��&�ר��e�����+yǢ�楖����l�+av'�z���ٚqן��ޭ�^�����ezx-�
+u�i��޶ȳzW�����r(�z�^���(����zW���p��~����r(�z�^�Ț��Zm�l�7�z۫�
+u�Z�ē--hn7��ן�x���_��_�霖'���t�f���zn+lzW߲,�םx��_�)��K�����Z�_}��_�)���7�H����jZ��݊x j�ii�����+ ��_�)�u�Z�mzV���-j�b�	hi��~�ށ���݊x?��b���+rf��M��t�����q�q�+��饧$z�(~�^�����_�鯕���_��o���zW�{�j���_v�fi����yu�|��q�]��,��w��^���y�+y�^���jiv�M,zW�v+ ��_�)�u�Z�]4�M4�ȳzǥ}�"��jǩ��-����4�G]u�4�_â�P�V��O�>���O4�Wl�]<�_��i��u�nl����M��d�-'��I2՘Yh�V������,�ɢ�����fkږ�zW�g%����ȳ{j)�w5o+^���nW�jx�]L�fZ�e�Z���jg�i�+r�-���z�t¸�z+m���������z�+q$�Ve�Z0U�߾v�zf���)��~ǭ �+r�߱�_���+b�f��(��z+�睶����b�f��L�f,H��(}����i�^�,�۞i�ԓ,�-�u���ڱ�d����ڵ�Z�ZvȳzW�m��Ko���z۫�$�J��jh���b�	ڙ��R�B'���
����i�٨u�-5¢{i��t�M��,��lI2Ŗ���l���My�+y�^���jiv�M,zW�v+ ��_�)�u�Z�]4�M4�ȳzǥ}�"��jǩ��-������G]u�4�_â�P�V��O�>���M��Wl�]7�_��i��u�nl����M��d�-'��I2՘Yh�V������,�ɢ�����fkږ�zW�g%����ȳ{j)�w5o+^���nW�jx�]L�fZ�e�Z���jg�i�+r�-���z�t¸�z+m���������z�+q$�Ve�Z0U�߾v�zf���)��~ǭ �+r�߱�_���+b�f��(��z+�睶����b�f��L�f,H��(}����i�^�,�۞i�ԓ,�-�u���ڱ�d����ڵ�Z�ZvȳzW�m��Ko���z۫�$�J��jh���b�	ڙ��R�B'���
����i�٨u�-5¢{i��t�M��,��lI2Ŗ���l���My�+y�^���jiw�M,zW�v+ ��_�)�u�Z�]4�M4�ȳzǥ}�"��jǩ��-����t�G]u�4�Wl�ǥ}�-��?�uB�Z��? �+s]=�M]��t�]5�@�v�+�]6��h��tۛ�I2�qY�k�-Y���j�ڙ�r�ܚ)�j[��f���nzǥ~{�rX���,�7����sV��ڮ&�z����u�$�Ve�Z0U�߾v�zf���)��~ǭ�L+�ע��Hz�^�w���L�fZ�e�Z���jg�i�+r�-���z���(}��������+6o+^��az�����y�h~,n�)�o+^�$�VabĊo�߱�H=Ɯ��"����-I2ϒ�n�W^��-m��K��ޭ�^�����l�7�zvڱ�d���������L���榊�-v+ ���H�� ?t�R'���
����i�٨u�-5¢{i��t�M��,��lI2Ŗ���l���My�+y�^���t�ǥ}��z���-�^����M4u�]�M5v�_}��}��}���uB�Z��?鲷5��4�,��t�G]u�4�Xpv�}�Mu�t�Miv�u��4 STLVmWrFlowVar(fv_name="mac_src", pkt_offset= 10),                                        
                           STLVmWrFlowVar(fv_name="mac_src" ,pkt_offset="ARP.psrc",offset_fixup=2),                
                           STLVmWrFlowVar(fv_name="mac_src" ,pkt_offset="ARP.hwsrc",offset_fixup=4),
                           STLVmWrFlowVar(fv_name="mac_src" ,pkt_offset="ARP.pdst",offset_fixup=2),                
                           STLVmWrFlowVar(fv_name="mac_src" ,pkt_offset="ARP.hwdst",offset_fixup=4),
                          ]
                        )
        pkt = STLPktBuilder(pkt=base_garp_pkt, vm=vm)

        return STLStream( name = 'S_L3_GARP_900',
                          packet = pkt,
                          mode = STLTXSingleBurst( pps = 100, total_pkts = self.num_clients),
                          next = 'NULL_900')
                         
    def create_garp_dummy_900(self):
        t_isg = self.time_sec * 1000000.0
        return STLStream( self_start = False,
                          isg = t_isg, 
                          name = 'NULL_900',
                          mode = STLTXSingleBurst(),
                          dummy_stream = True,
                          next = 'S_L3_GARP_900')

    def create_stream_l3_700 (self):
        td_isg = self.time_delay * 1000000.0
        size = self.fsize - 4;
        base_pkt =  Ether(src = "70:00:dd:dd:00:01", dst = self.dst_mac )/Dot1Q(vlan=70)/IP(src="10.70.0.1",dst="10.71.0.1")/UDP(dport=1025,sport=1025)
        vm = STLScVmRaw( [ STLVmFlowVar(name="mac_src", min_value=1, max_value=self.num_clients, size=2, op="inc"), # 1 byte varible, range 1-10
                           STLVmWrFlowVar(fv_name="mac_src", pkt_offset= 10),                          # write it to LSB of ethernet.src 
                           STLVmWrFlowVar(fv_name="mac_src" ,pkt_offset="IP.src",offset_fixup=2),       # it is 2 byte so there is a need to fixup in 2 bytes
                           STLVmFixIpv4(offset = "IP")
                          ],
                          cache_size=255
                        )
        pkt = STLPktBuilder(pkt=base_pkt/generate_payload(size-len(base_pkt)), vm=vm)
        return STLStream( isg = td_isg,
                          name='S_L3_VID70_71_IntraDC', 
                          packet = pkt,
                          mode = STLTXCont( pps = 10000 ),
                          flow_stats = STLFlowStats( pg_id = 700)
                          )

    def create_garp_l3_700 (self):
        base_garp_pkt =  Ether(src = "70:00:dd:dd:00:01", dst="ff:ff:ff:ff:ff:ff")/Dot1Q(vlan=70)/ARP(psrc="10.70.0.1", hwsrc="70:00:dd:dd:00:01", hwdst="70:00:dd:dd:00:01", pdst="10.70.0.1")
        vm = STLScVmRaw( [ STLVmFlowVar(name="mac_src", min_value=1, max_value=self.num_clients, size=2, op="inc"),
                           STLVmWrFlowVar(fv_name="mac_src", pkt_offset= 10),                                        
                           STLVmWrFlowVar(fv_name="mac_src" ,pkt_offset="ARP.psrc",offset_fixup=2),                
                           STLVmWrFlowVar(fv_name="mac_src" ,pkt_offset="ARP.hwsrc",offset_fixup=4),
                           STLVmWrFlowVar(fv_name="mac_src" ,pkt_offset="ARP.pdst",offset_fixup=2),                
                           STLVmWrFlowVar(fv_name="mac_src" ,pkt_offset="ARP.hwdst",offset_fixup=4),
                          ]
                        )
        pkt = STLPktBuilder(pkt=base_garp_pkt, vm=vm)

        return STLStream( name = 'S_L3_GARP_700',
                          packet = pkt,
                          mode = STLTXSingleBurst( pps = 100, total_pkts = self.num_clients),
                          next = 'NULL_700')
                         
    def create_garp_dummy_700(self):
        t_isg = self.time_sec * 1000000.0
        return STLStream( self_start = False,
                          isg = t_isg, 
                          name = 'NULL_700',
                          mode = STLTXSingleBurst(),
                          dummy_stream = True,
                          next = 'S_L3_GARP_700')

    def get_streams (self, direction = 0, **kwargs):
        # create 1 stream 
        #self.streams = streams
        return [
          self.create_stream_l2_800(),
          self.create_stream_l2_300(),
          self.create_stream_l3_700(),
          self.create_stream_l3_900(),
          self.create_garp_l3_700(),
          self.create_garp_dummy_700(),
          self.create_garp_l3_900(),
          self.create_garp_dummy_900(),  
          ]
          
# dynamic load - used for trex console or simulator
def register():
    return STLS1()



��