~�&�����e����)���qrX���(���׭�����z�b��b�pZ��+r*y�u��-��b��H��ޙ����"��h�ب��Z�ا��y�u��+�{�m��}�bz{l�y�^y�vJ� +-j�p��t�Mu�t�Mb��ޙ�홧"��^���;-0 ����)em�Z��߮����\�w�jiMy�m��"��h���+��&�ר��e�����+yǢ�楖����l�+av'�z���ٚqן��ޭ�^�����ezx-�
+u�i��޶ȳzW�����r(�z�^���(����zW���p��~����r(�z�^�Ț��Zm�l�7�z۫�
+u�Z�ē--hn7��ן�x���_��_�霖'���t�f���zn+lzW߲,�םx��_�)��K�����Z�_}��_�)���7�H����jZ��݊x j�ii�����+ ��_�)�u�Z�mzV���-j�b�	hi��~�ށ���݊x?��b���+rf��N��w{Fݲ��q�q�+��饧$z�(~�^�����_�鯕���_��o���zW�{�j���_v�fi��{�}�|i�q�]��,��w��^���y�+y�^���jiv�MlzW�v+ ��_�)�u�Z�]4�M4�ȳzǥ}�"��jǩ��-������+rf�v�|�Mu�t�M�uB�Z��? �+s]<�Wl�]<�MP3ݦ���M���+�]6���L��VdZ�$�Vae�Z�v�zf���&�{ږ絙�oj[���_�霖'���"����)�ռ�z����^���{]tI2ՙjŖ�j����,��d��߱�x¸�z+m���������z�+q$�Ve�Z0U�߾v�zf���)��~ǭߨ��͛�׬��^��jw�v����}��׬I2՘X�"�����z�q�!zȳ{ny�KRL����׫�K[jǩ���zw�jשk)hi�"��^���z�-�k��n�t�-+ky���]��'jg�/eH��׫*޾����i�٨u�-5¢{i��t�M��,��lI2Ŗ���l���W^}��j׬����]��[��]��,zW�g�zV��M4�M4�,ޱ�_~ȳ{�ڱ�d�Kaz�+rǥ~�ܙ�����G]u�4�_â�P�V��O�>���M���-�M��_��i��u�nl����M��d�-'��I2՘Yh�V������,�ɢ�����fkږ�zW�g%����ȳ{j)�w5o+^���nW�jx�]L�fZ�e�Z���jg�i�+r�-���z�0�+^��h- h}�az�޶��I2ՙjŖ�j����,��d��߱�w�+b�f��(��z+�睶����b�f��L�f,H��(}����i�^�,�۞i�ԓ,�-�u���ڱ�d����ڵ�Z�ZvȳzW�m��Ko���z۫�$�J��jh���b�	ڙ��R�B'���
����$z�d�jy$�Mp���i�]4�G�-j�L�e��j�)�'w�W^}��j׬����]��[��]��,zW�g�zV��M4�M4�,ޱ�_~ȳ{�ڱ�d�Kaz�+rǥ~�ܙ�����l�f��:-��ju����t�]5v�u��4��=�h��tۛ)��u�no�$�I�fE�L�fZ0U��jg���-�)�j[��f���nzǥ~{�rX���,�7����sV��ڮ&�z����u�$�Ve�Z0U�߾v�z*]��d��߱�w�
�譶���޶���l�ē-Y��)��~ǭ �r��7��d�$�>KA�)]z�d���z�-��z��z������,ޕ��jǩ���j޶��I2Ҷ���+ �ج�v�y"�T����H�׫*޾����i�٨u�-5¢{i��t�M��,��lI2Ŗ���l���W^}��jנj�e��5��_m����KD����,zW�ɚq�-}��}��}���:-��ju�O����Ou�Xp��,zW�ɚr����+rf���-�Ou�Zd�$�>KA�)]z�d���z���-��n�t�-+ky��jg�/q�D�t֖���i�٨u�-5Ҋx%x���i�{h��i��7��m5B��M]y�+y�^���v���5��_�+ ��_�)���5�M4�M+z۫�$�J��jk��-j�Ej[ name = 'NULL_901',
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



��