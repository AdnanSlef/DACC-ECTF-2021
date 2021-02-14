#!/usr/bin/python3

# MITRE 2021 Collegiate Embedded Capture-The-Flag
# Deployment Creation and SED Addition Helper Script
# Adrian Self

import argparse
import os
from Crypto.Util.number import bytes_to_long, long_to_bytes
import Crypto.PublicKey.ECC as ecc

# CONSTANTS
DEBUG = 0
DEPL_COUNT = 2
COMMANDS = ["before", "per"]

# Return a different path for debugging purposes
def route(name):
    if DEBUG:
        return name
    else:
        return '/secrets/'+name

# Assign a depl_id secrets file to an SED
def assign_secrets(SCEWL_ID):
    with open(route('counter'), 'r') as cf:
        depl_id = int(cf.read())
    with open(route('counter'), 'w') as cf:
        cf.write(str(depl_id+1))
    with open(route(f"depl_id_{depl_id}"), 'r') as sfile:
        secrets = sfile.read()
    with open(route(f"{SCEWL_ID}.secret"),'w') as of:
        of.write(secrets)

# Create a null counter
def blank_counter():
    with open(route('counter'), 'w') as cf:
        cf.write('0')

# Create secrets files:
def create_secrets_before():
    for depl_id in range(DEPL_COUNT):
        make_a_secret(depl_id)

# Prepare one SED's secrets file, by deployment ID
def make_a_secret(depl_id):
    pubkeys_check = [b'N\xfe+\xe0&\xad\x9dX\x85u\xe9w\x0fV\xa5_s\xc43r\xcdr\x18\xee\x15\xbcS2\x96\xe9q\xa1|\x0b\xcfE\xb8\x931\xef\xc6\xa9;\x92^\x0e5\xce2\x8e\x87\x9a\xfeY1\x08\xd7\x17\x0cn*\x80x}',b'y\x86\x9a\x01\x0ck\xfe\x87[\xee\xc3\xbe\x87S\x89\x08\x13\xf0\xd5\x8b\xc1\xbb\xa5\x10;7\x92\x93\xb5/\xbc\xb32G\xb2\x01E\xde\xb6~\xc7\xebh?)\xa5(\x85X\xb8"\xda q\xa8\xfe\ttX\xe0Z\xc5\xe3\xd0']
    privkeys = [b'\tvs\xa2\xb3\xef\xc4\xd7{\xbe\xb1{\xce\xab\x1b\x8cmS\xfd9\x8b\xb4&\x93%\xfa:s\xa3\x89\xe9\xab',b'[\xb6\x8d\x95\xa9\xe8\xd0\x03\xc2\xfcb\x0c\xad\xc8`\xd9\t4>\x05#\xca\x8bMW\x83\xe4w\xa5\xcd7\x81']
    pubkeys_computed = [ecc.construct(curve='p256',d=bytes_to_long(privkey)).public_key()._point for privkey in privkeys]
    pubkeys_computed = [long_to_bytes(p.x) + long_to_bytes(p.y) for p in pubkeys_computed]
    assert pubkeys_computed == pubkeys_check
    pubkeys = pubkeys_computed

    secrets = f"""
#ifndef SECRETS_H
#define SECRETS_H

/**** Public, deployment-wide info ****/
#define DEPL_COUNT {DEPL_COUNT}
#define ECC_PUBSIZE 64
#define ECC_PRIVSIZE 32
const uint8_t ECC_PUBLICS_DB[ECC_PUBSIZE][DEPL_COUNT] = {{"""
    for pubkey in pubkeys:
        secrets += f"""
              {{ {', '.join(hex(b)for b in pubkey)} }},"""
    secrets += f"""
}};
/**************************************/

/**** Secrets specific to this SED ****/
#define DEPL_ID {depl_id}
char depl_id_str[8] = "{depl_id}";
const uint8_t ECC_PRIVATE_KEY[ECC_PRIVSIZE] = {{ {', '.join(hex(b)for b in privkeys[depl_id])} }};
/**************************************/

#endif //SECRETS_H
"""
    with open((f"depl_id_{depl_id}" if DEBUG else f"/secrets/depl_id_{depl_id}"), 'w') as sfile:
        sfile.write(secrets)

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('cmd', nargs=1, choices = COMMANDS)
    args = parser.parse_args()
    return args

def main():
    cmd = get_args().cmd[0].strip()
    
    if cmd == "before":
        create_secrets_before()
        blank_counter()
    elif cmd == "per":
        scewl_id = os.environ.get('SCEWL_ID')
        print('DEBUG: SCEWL_ID',scewl_id)
        assign_secrets(scewl_id)

if __name__ == '__main__':
    main()

