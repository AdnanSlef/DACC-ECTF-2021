#!/usr/bin/python3

# MITRE 2021 Collegiate Embedded Capture-The-Flag
# SED Data Vault for the Scewl Security Server
# Adrian Self

import os
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes
import Crypto.PublicKey.ECC as ecc

class :
    def __init__(self):
        
class Vault:
    def __init__(self, fname):#TODO params
        self.fname = fname
        create(self)

    def create(self):
        self.auth  = b''
        self.crypt = {"ecc_priv":b'', "brd_priv":b'', "ecc_pubs":b'', "brd_pub":b''}
        self.store = {}
        self.keys  = {}

    def retr(self, key=''):
        pass
        return v[key] if key else v

    def store(self, auth, seq=1):
        pass

    # Read vault from disk
    def pull(self):
        pass

    # Wrtie vault to disk
    def push(self):
        pass

