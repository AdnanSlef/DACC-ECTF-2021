#!/usr/bin/python3

# MITRE 2021 Collegiate Embedded Capture-The-Flag
# Deployment Creation and SED Addition Helper Script
# Adrian Self

import argparse
import os
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes
import Crypto.PublicKey.ECC as ecc

# CONSTANTS
DEBUG = 0
DEPL_COUNT = 2 #TODO change
NUM_SEEDS = 256
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
    privkeys = [b'\tvs\xa2\xb3\xef\xc4\xd7{\xbe\xb1{\xce\xab\x1b\x8cmS\xfd9\x8b\xb4&\x93%\xfa:s\xa3\x89\xe9\xab',b'[\xb6\x8d\x95\xa9\xe8\xd0\x03\xc2\xfcb\x0c\xad\xc8`\xd9\t4>\x05#\xca\x8bMW\x83\xe4w\xa5\xcd7\x81'] #TODO securely generate
    # Calculate public key points
    pubkeys = [ecc.construct(curve='secp256r1',d=bytes_to_long(privkey)).public_key()._point for privkey in privkeys]
    pubkeys = [long_to_bytes(point.x) + long_to_bytes(point.y) for point in pubkeys] #format for uECC
    entropy = [get_random_bytes(32) for _ in range(NUM_SEEDS)]
    nonce = get_random_bytes(16)

    secrets = f"""
#ifndef SECRETS_H
#define SECRETS_H

/**** Public, deployment-wide info ****/
#define DEPL_COUNT {DEPL_COUNT}
#define ECC_PUBSIZE 64
#define ECC_PRIVSIZE 32
#define NUM_SEEDS {NUM_SEEDS}
uint8_t ECC_PUBLICS_DB[DEPL_COUNT][ECC_PUBSIZE] = {{"""
    for pubkey in pubkeys:
        secrets += f"""
              {{ {', '.join(hex(b)for b in pubkey)} }},"""
    secrets += f"""
}};
uint16_t SCEWL_IDS_DB[DEPL_COUNT] = {{10,11}};//TODO populated at registration
/**************************************/

/**** Secrets & info specific to this SED ****/
#define DEPL_ID {depl_id}
uint64_t seq = 1;
uint16_t seed_idx = 0;
char depl_id_str[8] = "{depl_id}";
uint8_t ECC_PRIVATE_KEY[ECC_PRIVSIZE] = {{ {', '.join(hex(b)for b in privkeys[depl_id])} }};
uint64_t KNOWN_SEQS[DEPL_COUNT] = {{ {', '.join('0' for _ in range(DEPL_COUNT))} }};
uint8_t ENTROPY[NUM_SEEDS][32] = {{"""
    for seed in entropy:
        secrets += f"""
              {{ {', '.join(hex(b)for b in seed)} }},"""
    secrets += f"""
}};
uint8_t NONCE[16] = {{ {', '.join(hex(b)for b in nonce)} }};
/*********************************************/

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

