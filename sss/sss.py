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
import json
from hmac import compare_digest
from typing import NamedTuple
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes


SSS_ID = 1
DEPL_COUNT = 256

# mirroring scewl_sss_op_t enum at scewl_bus.h:53
ALREADY, REG, DEREG = -1, 0, 1

logging.basicConfig(level=logging.DEBUG)

Device = NamedTuple('Device', [('id', int), ('csock', socket.socket)])

sizeof = {'scewl_sss_msg_t':4, 'sss_reg_req_t':20, 'sss_reg_rsp_t':2656, 'sss_dereg_req_t':2080, 'sss_dereg_rsp_t':4}

# determine whether bytes objects are equivalent
def bequal(chall, guess):
    return compare_digest(guess, chall)

# make sure dict from json has correct types
def intify(d):
    return dict(zip( map(int,d.keys()), map(int,d.values()) ))

# try to recv a whole buffer
def realrecv(csock, n):
    data = b''
    while len(data) < n:
        recvd = csock.recv(min(n - len(data), 1024))
        data += recvd

        # check for closed connection
        if not recvd:
            logging.debug(f'Detected closed connection while trying to recv {n} bytes')
            raise ConnectionResetError
    return data[:n]

# try to send a whole buffer
def realsend(csock, buf):
    totalsent = 0
    while totalsent < len(buf):
        sent = csock.send(buf[totalsent:])

        # check for closed connection
        if not sent:
            logging.debug('Detected closed connection when looking for registration req')
            raise ConnectionResetError
        totalsent += sent
    logging.debug(f"successfully sent {totalsent} bytes")

class SSS:
    def __init__(self, sockf, depl_nonce, mapping, auth):
        self.depl_nonce = depl_nonce
        self.mapping = mapping
        self.reverse_map = {scewl_id:depl_id for depl_id, scewl_id in mapping.items()}
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
        self.registered = []
    
    @staticmethod
    def sock_ready(sock, op='r'):
        rready, wready, _ = select.select([sock], [sock], [], 0)
        return rready if op == 'r' else wready
    
    # prepare the SCEWL <--> DEPL mapping for an SED
    def create_map(self, SCEWL_ID):
        BAD_ID = SCEWL_ID
        arr = [BAD_ID] * DEPL_COUNT
        for depl_id in range(DEPL_COUNT):
            if depl_id in self.mapping:
                arr[depl_id] = self.mapping[depl_id]
        return arr

    def handle_registration(self, dev_id, csock):
        #define deployment id
        try:
            depl_id = self.reverse_map[dev_id]
        except:
            logging.info("failed reverse lookup in registration")
            return

        # receive rest of registration request
        data = realrecv(csock, sizeof['sss_reg_req_t']-sizeof['scewl_sss_msg_t'])
        logging.debug(f'Received registration buffer: {repr(data)}')
        auth = data
        
        # verify authentication token
        if not bequal(self.auth[dev_id], auth):
            logging.info(f"{dev_id} failed registration auth")
            return
        logging.info(f"{dev_id} passed registration auth")

        # form a registration response
        '''
// registration response message (2656B)
typedef struct sss_reg_rsp_t {
  scewl_sss_msg_t basic;
  uint32_t padding;
  uint16_t ids_db[DEPL_COUNT];     //maps SCEWL ids to deployment ids
  uint64_t seq;                    //this SED's sequence number
  uint64_t known_seqs[DEPL_COUNT]; //last-seen seq numbers
  uint8_t  cryptkey[16]; //key to unlock ecc
  uint8_t  cryptiv[16];  // iv to unlock ecc
  uint8_t  entropky[16]; //just random bytes
  uint8_t  entriv[16];   //"               "
  uint8_t  depl_nonce[16];   //replay protection
} sss_reg_rsp_t;
        '''
        basic = struct.pack('<2sHHHHh', b'SC', dev_id, SSS_ID, sizeof['sss_reg_rsp_t'], dev_id, REG)
        padding = struct.pack('>I', 0xC001DACC)
        ids_db = struct.pack('<256H', *self.create_map(dev_id))
        seq = struct.pack('<Q', 1) #TODO set and store seq
        known_seqs = struct.pack('<256Q', *[0]*256) #TODO set and store known_seqs
        with open(f'/secrets/{depl_id}.crypt','rb') as f:
            cryptkey = f.read(16)
            cryptiv = f.read(16)
        entropky = get_random_bytes(16)
        entriv = get_random_bytes(16)
        depl_nonce = self.depl_nonce

        # craft response from components
        rsp = basic + padding + ids_db + seq + known_seqs + cryptkey + cryptiv + entropky + entriv + depl_nonce

        # send registration response to SED
        logging.debug(f'Sending {dev_id} reg response ({len(rsp)}B): {repr(rsp)}')
        realsend(csock, rsp)
        
        # register in the SSS
        self.registered.append(dev_id)


    def handle_deregistration(self, dev_id, csock):
        # receive rest of deregistration request
        data = realrecv(csock, 0)#sizeof['sss_dereg_req_t'] - sizeof['scewl_sss_msg_t'])
        logging.debug(f'Received deregistration buffer: {repr(data)}')

        #unpack deregistration request
        '''
// deregistration request message (2080B)
typedef struct sss_dereg_req_t {
  scewl_sss_msg_t basic;
  uint32_t padding;
  uint8_t auth[16];
  uint64_t seq;
  uint64_t known_seqs[DEPL_COUNT];
} sss_dereg_req_t;
        '''
        '''TODO uncomment
        padding, auth, seq = struct.unpack('<I16sQ', data[:28])
        known_seqs = struct.unpack('<256Q', data[28:])
        '''
        auth = self.auth[dev_id] #TODO remove
        
        # verify authentication token
        if not bequal(self.auth[dev_id], auth):
            logging.info(f"{dev_id} failed deregistration auth")
            return
        logging.info(f"{dev_id} passed deregistration auth")
        
        #store seq and known_seqs in vault
        #TODO

        rsp = struct.pack('<2sHHHHh', b'SC', dev_id, SSS_ID, 4, dev_id, DEREG)
        
        # send deregistration response to SED
        logging.debug(f'Sending {dev_id} dereg response {repr(rsp)}')
        realsend(csock, rsp)
        
        # deregister in the SSS
        self.registered.remove(dev_id)


    def handle_transaction(self, csock: socket.SocketType):
        logging.debug('handling transaction')

        # receive basic request
        data = realrecv(csock, 12)
        logging.debug(f'Received basic buffer: {repr(data)}')

        #unpack basic request
        _sc, _tgt, _src, _len, dev_id, op = struct.unpack('<HHHHHH', data)

        # attribute socket
        self.devs[dev_id] = Device(dev_id, csock)

        logging.info(f"{{ {self.registered} }} devices are registered")

        # handle registration
        if op == REG and dev_id not in self.registered and len(self.registered)<16:
            logging.info(f'{dev_id} is asking to register')
            self.handle_registration(dev_id, csock)

        # handle deregistration
        elif op == DEREG and dev_id in self.registered:
            logging.info(f'{dev_id} is asking to deregister')
            self.handle_deregistration(dev_id, csock)

        # no operation could be performed
        else:
            logging.info(f'{dev_id} was denied operation {op}')


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

# pulls scewl <--> depl id mapping from disk
def get_mapping():
    #return {0:10,1:11}
    with open('/secrets/mapping','r') as f:
        mapping = json.load(f)
    logging.debug(f"Found mapping on disk: {intify(mapping)}")
    return intify(mapping)

# pulls authentication tokens from disk
def get_auth(mapping):
    with open('/secrets/auth','r') as f:
        tokens = json.load(f)
    tokens = intify(tokens)
    useful_tokens = {}
    for depl_id in tokens:
        try:
            scewl_id = mapping[depl_id]
            useful_tokens[scewl_id] = long_to_bytes(tokens[depl_id],16)
        except Exception as e:
            logging.debug(f"{depl_id} unused")
    return useful_tokens

def main():
    args = parse_args()

    ### Here is where deploy-time tasks are run

    # generate depl_nonce
    depl_nonce = get_random_bytes(16)

    # pull mapping to SSS RAM, {depl_id : scewl_id}
    mapping = get_mapping()

    # pull AUTH dict to SSS RAM, {scewl_id : auth_token}
    auth = get_auth(mapping)
    logging.debug(f'auth = {auth}')

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
