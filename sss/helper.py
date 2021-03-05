#!/usr/bin/python3

# MITRE 2021 Collegiate Embedded Capture-The-Flag
# Deployment Creation and SED Addition Helper Script
#
# 0xDACC
# Adrian Self
# Delaware Area Career Center

import argparse
import os
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes
import Crypto.PublicKey.ECC as ecc

# CONSTANTS
ECC_PRIVSIZE = 32
ECC_PUBSIZE = ECC_PRIVSIZE * 2
DEPL_COUNT = 256
NUM_SEEDS = 256
COMMANDS = ["before", "per"]

# Create secrets files:
def create_secrets_before():
    # Generate private keys
    privkeys = [ecc.generate(curve='secp256r1') for _ in range(DEPL_COUNT)]

    # Calculate public key points
    pubkeys = [ecc.construct(curve='secp256r1',d=privkey.d).public_key()._point for privkey in privkeys]

    # Generate broadcast keys
    brdcst_privkey = ecc.generate(curve='secp256r1')
    brdcst_public = ecc.construct(curve='secp256r1',d=brdcst_privkey.d).public_key()._point
    brdcst_keys = [brdcst_privkey,brdcst_public]

    # Uniquely identify this deployment
    depl_nonce = get_random_bytes(16)

    # Generate secrets for each depl_id
    for depl_id in range(DEPL_COUNT):
        make_a_secret(depl_id, depl_nonce, privkeys[depl_id], pubkeys, brdcst_keys)

# Prepare one SED's secrets file, by deployment ID
def make_a_secret(depl_id, depl_nonce, privkey, pubkeys, brdcst_keys):
    # Pack keys for use in the Controller
    privkey = long_to_bytes(privkey.d, ECC_PRIVSIZE)
    pubkeys = [long_to_bytes(point.x, ECC_PRIVSIZE) + long_to_bytes(point.y, ECC_PRIVSIZE) for point in pubkeys]
    brdcst_privkey = long_to_bytes(brdcst_keys[0].d, ECC_PRIVSIZE)
    brdcst_public = long_to_bytes(brdcst_keys[1].x, ECC_PRIVSIZE) + long_to_bytes(brdcst_keys[1].y, ECC_PRIVSIZE)
    
    # Provide a source of randomness
    entropy = [get_random_bytes(32) for _ in range(NUM_SEEDS)]
    nonce = get_random_bytes(16)

    # Authorize the SED as part of the deployment
    auth = get_random_bytes(16)
    try:
        with open('/secrets/auth','r') as f:
            tokens = json.load(f)
    except:
        tokens = {}
    tokens[depl_id] = bytes_to_long(auth)
    with open('/secrets/auth','w') as f:
        json.dump(tokens, f)

    # Create vault file with secrets for SSS usage

    # Create header file with secrets for SED Controller usage
    secrets = f"""
#ifndef SECRETS_H
#define SECRETS_H

/**** Non-confidential values from add_sed ****/
#define DEPL_COUNT {DEPL_COUNT}
#define DEPL_ID {depl_id}
#define DEPL_BRDCST_ID 0xFFFF
#define ECC_PUBSIZE {ECC_PUBSIZE}
#define ECC_PRIVSIZE {ECC_PRIVSIZE}
#define SLOTH 0 // seconds to send 0x100 bytes of data (TODO 30)
#define ONE_SECOND 0x10000000 // iterations needed to wait one second
#define NUM_SEEDS {NUM_SEEDS}
uint16_t seed_idx = 0;
char depl_id_str[8] = "{depl_id}";
int registered = 0;
/**********************************************/

/**** Values distributed during registration ****/
uint64_t seq = 1;
uint64_t KNOWN_SEQS[DEPL_COUNT] = {{ {', '.join('0' for _ in range(DEPL_COUNT))} }};

uint16_t SCEWL_IDS_DB[DEPL_COUNT] = {{ {', '.join([str(x) for x in range(10,10+DEPL_COUNT)])} }};//TODO populated at registration

uint8_t ENTROPY[NUM_SEEDS][32] = {{"""
    for seed in entropy:
        secrets += f"""
              {{ {', '.join(hex(b)for b in seed)} }},"""
    secrets += f"""
}};
uint8_t NONCE[16] = {{ {', '.join(hex(b)for b in nonce)} }};

uint8_t AUTH[16] = {{ {', '.join(hex(b)for b in auth)} }};
uint8_t depl_nonce[16] = {{ {', '.join(hex(b)for b in depl_nonce)} }};

uint8_t ECC_PUBLICS_DB[DEPL_COUNT][ECC_PUBSIZE] = {{"""
    for pubkey in pubkeys:
        secrets += f"""
              {{ {', '.join(hex(b)for b in pubkey)} }},"""
    secrets += f"""
}};
uint8_t BRDCST_PUBLIC[ECC_PUBSIZE] = {{ {', '.join(hex(b)for b in brdcst_public)} }};
uint8_t ECC_PRIVATE_KEY[ECC_PRIVSIZE] = {{ {', '.join(hex(b)for b in privkey)} }};
uint8_t BRDCST_PRIVATE_KEY[ECC_PRIVSIZE] = {{ {', '.join(hex(b)for b in brdcst_privkey)} }};
/*************************************************/

#endif //SECRETS_H
"""

    with open(f"/secrets/depl_id_{depl_id}", 'w') as sf:
        sf.write(secrets)

# Create a null counter
def blank_counter():
    with open('/secrets/counter', 'w') as cf:
        cf.write('0')

# Assign a depl_id secrets file to an SED
def assign_secrets(SCEWL_ID):
    with open('/secrets/counter', 'r') as cf:
        depl_id = int(cf.read())
    assert depl_id < DEPL_COUNT
    with open('/secrets/counter', 'w') as cf:
        cf.write(str(depl_id+1))
    with open(f"/secrets/depl_id_{depl_id}", 'r') as sf:
        secrets = sf.read()
    with open(f"/secrets/{SCEWL_ID}.secret",'w') as of:
        of.write(secrets)

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('cmd', nargs=1, choices = COMMANDS)
    args = parser.parse_args()
    return args

def main():
    cmd = get_args().cmd[0].strip()
    
    if cmd == "before":
        #prepare deployment
        create_secrets_before()
        blank_counter()
    elif cmd == "per":
        #add an SED
        scewl_id = os.environ.get('SCEWL_ID')
        assign_secrets(scewl_id)

if __name__ == '__main__':
    main()
