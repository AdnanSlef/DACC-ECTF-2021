#!/usr/bin/python3

# MITRE 2021 Collegiate Embedded Capture-The-Flag
# Deployment Creation and SED Addition Helper Script
# Adrian Self

import argparse
import os

# CONSTANTS
DEBUG = 1
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
    with open(route(f"{SCEWL_ID}.secrets"),'w') as of:
        of.write(secrets)

# Create a null counter
def blank_counter():
    with open(route('counter'), 'w') as cf:
        cf.write('0')

# Create secrets files:
def create_secrets_before():
    for depl_id in range(DEPL_COUNT):
        make_a_secret(depl_id)

def make_a_secret(depl_id):
    pubkeys = [b'\x06\xb6X\xbep\x1a\x05\x07\xeb,\x95\x93\x89\x10!\xea\x0fB)\xca\xe9\x17\x14\\\x98\xaed\xfcd\xc3w\xfd\xf5&W\xb0^&\x80\xb7\x8eA\x13$\n\xe2\x7f+Jk\x04\xd8\xd8\x87\xacqO]|\x02\xfc \xca\xd8', b'\xd2\xf7\x17\xea6\xd6\x8d!\xcd\x8a\xb4L\x8bL\xbb\x19\xe5\xe3\xd5\xa8@bi\xc0\x1c"\xeb\x99\xf9=Y\xda\xb2z\xb5O}p\xeb?\xa3\xc97\x0f\x02\xc2wp3=\x7f\xb4e\xc5\x14\xcdGZ\tz\xe1\x08\xc7n']

    secrets = f"""
#ifndef SECRETS_H
#define SECRETS_H

#define DEPL_COUNT {DEPL_COUNT}
#define ECC_PUBSIZE 64
const uint8_t ECC_PUBLICS_DB[ECC_PUBSIZE][DEPL_COUNT] = {{"""
    for pubkey in pubkeys:
        secrets += f"""
              {{ {', '.join(hex(b)for b in pubkey)} }},"""
    secrets += f"""
}};

#endif //SECRET_H
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

