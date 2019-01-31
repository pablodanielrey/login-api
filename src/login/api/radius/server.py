
import asyncio

import logging
import traceback
import hmac
import struct
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessAccept, AccessChallenge
from pyrad.server import RemoteHost

# hasta que hagan el release de la nueva versión de pyrad que incluya esta clase
from .server_async import ServerAsync


class RadiusServer(ServerAsync):

    def __init__(self, loop, dictionary):

        ServerAsync.__init__(self, loop=loop, dictionary=dictionary,
                             enable_pkt_verify=True, debug=True)

    def _printpkg(self, pkt):
        print("Id ", pkt.id)
        print('Authenticator ', pkt.authenticator.hex())
        print('Secret ', pkt.secret)
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))
        print("\n\n")


    def _sign_reply(self, authenticator, reply):
        hmac_obj = hmac.new(reply.secret)
        hmac_obj.update(struct.pack("B", reply.code))
        hmac_obj.update(struct.pack("B", reply.id))

        # reply attributes
        reply.AddAttribute("Message-Authenticator",
                            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        attrs = reply._PktEncodeAttributes()

        # Length
        flen = 4 + 16 + len(attrs)
        hmac_obj.update(struct.pack(">H", flen))
        hmac_obj.update(authenticator)
        hmac_obj.update(attrs)
        del reply[80]
        reply.AddAttribute("Message-Authenticator", hmac_obj.digest())


    def _get_eap_code(self, eap_code):
        if eap_code == 1:
            return 'Request'
        if eap_code == 2:
            return 'Response'
        if eap_code == 3:
            return 'Success'
        if eap_code == 4:
            return 'Failure'

    def _get_eap_type(self, eap_type):
        if eap_type == 1:
            return 'Identity'
        if eap_type == 2:
            return 'Notification'
        if eap_type == 3:
            return 'Nak (Response only)'
        if eap_type == 4:
            return 'MD5-Challenge'
        if eap_type == 5:
            return 'One Time Password (OTP)'
        if eap_type == 6:
            return 'Generic Token Card (GTC)'
        if eap_type == 254:
            return 'Expanded Types'
        if eap_type == 255:
            return 'Experimental use'
        return 'Unknown'


    def _disect_eap_message(self, eap):
        eap_code, eap_identifier, length = struct.unpack('!BBH', eap[:4])
        eap_data = eap[4:length]
        print('EAP-CODE: {} ({})'.format(eap_code, self._get_eap_code(eap_code)))
        print('EAP-ID: ', eap_identifier)
        print('EAP-LENGTH: ', length)
        print('EAP-DATA: {}'.format(eap_data))

        (eap_type,) = struct.unpack('!B', bytes(eap_data[:1], 'utf8'))
        eap_type_data = eap_data[1:]

        print('EAP-TYPE: {} ({})'.format(eap_type, self._get_eap_type(eap_type)))
        print('EAP-TYPE-DATA:', eap_type_data)








    def handle_auth_packet(self, protocol, pkt, addr):

        print('Autenticación')
        self._printpkg(pkt)

        reply = self.CreateReplyPacket(pkt)
        reply.code = AccessChallenge

        eap = pkt['EAP-Message'][0]
        print('EAP: {}'.format(eap))
        self._disect_eap_message(eap)



        """
        eap_req = self.eap_handler(self.ctx, eap)
        if eap_req:
            while True:
                if len(eap_req) > 253:
                    reply.AddAttribute("EAP-Message", eap_req[0:253])
                    eap_req = eap_req[253:]
                else:
                    reply.AddAttribute("EAP-Message", eap_req)
                    break
        else:
            logger.info("No EAP request available")
        """
        reply.AddAttribute('EAP-Message', eap)

        self._sign_reply(pkt.authenticator, reply)

        print('Respondiendo')
        self._printpkg(reply)

        protocol.send_response(reply, addr)



    def _handle_auth_packet_portalcaptivo(self, protocol, pkt, addr):

        #if '27294557' in pkt['User-Name']:
        print("Received an authentication request with id ", pkt.id)
        print('Authenticator ', pkt.authenticator.hex())
        print('Secret ', pkt.secret)
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))
        print("\n\n")

        """
        reply = self.CreateReplyPacket(pkt, **{
            "Service-Type": "Framed-User",
            "Framed-IP-Address": '192.168.0.1',
            "Framed-IPv6-Prefix": "fc66::1/64"
        })
        """

        '''
            se reponde con timeout de 1 hora
        '''
        reply = self.CreateReplyPacket(pkt, **{
            "Session-Timeout": '3600'
        })

        reply.code = AccessAccept
        protocol.send_response(reply, addr)

    def handle_acct_packet(self, protocol, pkt, addr):

        print("Received an accounting request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        protocol.send_response(reply, addr)

    def handle_coa_packet(self, protocol, pkt, addr):

        print("Received an coa request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        protocol.send_response(reply, addr)

    def handle_disconnect_packet(self, protocol, pkt, addr):

        print("Received an disconnect request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        # COA NAK
        reply.code = 45
        protocol.send_response(reply, addr)

