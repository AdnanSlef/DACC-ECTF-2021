#!/usr/bin/python3

# 2021 Collegiate eCTF
# SCEWL Security Server
#
# 0xDACC
# Adrian Self
# Delaware Area Career Center
#
# This source file is part of our design for MITRE's 2021 Embedded System CTF (eCTF).
# It provides secure registration and deregistration to supoprt Scewl Enabled Devices
# including UAVs, enabling secure communication between devices.

import socket
import select
import struct
import argparse
import logging
import os
from typing import NamedTuple
from Crypto.Random import get_random_bytes


SSS_ID = 1
DEPL_COUNT = 256

# mirroring scewl_sss_op_t enum at scewl_bus.h:53
ALREADY, REG, DEREG = -1, 0, 1

logging.basicConfig(level=logging.DEBUG)

Device = NamedTuple('Device', [('id', int), ('csock', socket.socket)])

sizeof = {'scewl_sss_msg_t':4, 'sss_reg_req_t':20, 'sss_reg_rsp_t':2656, 'sss_dereg_req_t':2080, 'sss_dereg_rsp_t':4}

class SSS:
    def __init__(self, sockf, depl_nonce, mapping, auth):
        self.depl_nonce = depl_nonce
        self.mapping = mapping
        self.auth = auth

        # Make sure the socket does not already exist
        try:
            os.unlink(sockf)
        except OSError:
            if os.path.exists(sockf):
                raise

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(sockf)
        self.sock.listen(20)

        self.devs = {}
    
    @staticmethod
    def sock_ready(sock, op='r'):
        rready, wready, _ = select.select([sock], [sock], [], 0)
        return rready if op == 'r' else wready
    
    # prepare the SCEWL <--> DEPL mapping for an SED
    def packed_map(self, SCEWL_ID):
        BAD_ID = SCEWL_ID
        arr = [BAD_ID] * DEPL_COUNT
        for depl_id in range(DEPL_COUNT):
            if depl_id in self.mapping:
                arr[depl_id] = self.mapping[depl_id]
        struct.pack('<256H', *arr)

    def handle_registration(self, dev_id, csock):
        rsp = struct.pack('<2sHHHHh', b'SC', dev_id, SSS_ID, 4, dev_id, REG)
        
        logging.debug(f'Sending {dev_id} reg response {repr(rsp)}')
        csock.send(rsp)
        self.devs[dev_id] = Device(dev_id, csock)

    def handle_deregistration(self, dev_id, csock):
        rsp = struct.pack('<2sHHHHh', b'SC', dev_id, SSS_ID, 4, dev_id, DEREG)

        logging.debug(f'Sending {dev_id} dereg response {repr(rsp)}')
        csock.send(rsp)
        del self.devs[dev_id]

    def handle_transaction(self, csock: socket.SocketType):
        logging.debug('handling transaction')

        # receive basic req
        data = b''
        while len(data) < 12:
            recvd = csock.recv(12 - len(data))
            data += recvd

            # check for closed connection
            if not recvd:
                logging.debug('Detected closed connection when looking for basic req')
                raise ConnectionResetError
        logging.debug(f'Received buffer: {repr(data)}')
        _sc, _tgt, _src, _len, dev_id, op = struct.unpack('<HHHHHH', data)

        # requesting registration
        if op == REG and dev_id not in self.devs and len(self.devs)<16:# and self.sock_ready(csock):
            logging.info(f'{dev_id} is asking to register')
            self.handle_registration(dev_id, csock)

        # requesting deregistration
        elif op == DEREG and dev_id in self.devs:# and self.sock_ready(csock):
            logging.info(f'{dev_id} is asking to deregister')
            self.handle_deregistration(dev_id, csock)

        # no operation could be performed
        else:
            logging.info(f'{dev_id} was denied operation {op}')
            resp_op = op


    def start(self):
        unattributed_socks = set()

        # serve forever
        while True:
            # check for new client
            if self.sock_ready(self.sock):
                csock, _ = self.sock.accept()
                logging.info(f':New connection')
                unattributed_socks.add(csock)
                continue

            # check pool of unattributed sockets first
            for csock in unattributed_socks:
                try:
                    if self.sock_ready(csock):
                        self.handle_transaction(csock)
                        unattributed_socks.remove(csock)
                        break
                except (ConnectionResetError, BrokenPipeError):
                    logging.info(':Connection closed')
                    unattributed_socks.remove(csock)
                    csock.close()
                    break
            
            # check pool of attributed sockets
            old_ids = []
            for dev in self.devs.values():
                if dev.csock and self.sock_ready(dev.csock):
                    try:
                        self.handle_transaction(dev.csock)
                    except (ConnectionResetError, BrokenPipeError):
                        logging.info(f'{dev.id}:Connection closed')
                        dev.csock.close()
                        old_ids.append(dev.id)
            
            for dev_id in old_ids:
                del self.devs[dev_id]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('sockf', help='Path to socket to bind the SSS to')
    return parser.parse_args()


def main():
    args = parse_args()

    # Here is where deploy-time tasks are run

    # generate depl_nonce
    depl_nonce = get_random_bytes(16)

    # TODO pull mapping to SSS RAM, {depl_id : scewl_id}
    mapping = {}

    # TODO pull AUTH dict to SSS RAM, {scewl_id : auth_token}
    auth = {}

    ### End deploy-time tasks

    # Construct SSS
    sss = SSS(args.sockf, depl_nonce, mapping, auth)

    # Serve in loop
    sss.start()


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logging.info(f'Dying with Exception: {e}')
        while(1):
            pass
