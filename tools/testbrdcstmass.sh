#!/bin/bash

# 2021 Collegiate eCTF
# Launch a test echo deployment
# Ben Janis
#
# (c) 2021 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!

set -e
set -m

if [ ! -d ".git" ]; then
    echo "ERROR: This script must be run from the root of the repo!"
    exit 1
fi

export DEPLOYMENT=echo
export SOCK_ROOT=$PWD/socks
export SSS_SOCK=sss.sock
export FAA_SOCK=faa.sock
export MITM_SOCK=mitm.sock
export START_ID=161
export END_ID=169
export SC_PROBE_SOCK=sc_probe.sock
export SC_RECVR_SOCK=sc_recvr.sock

# create deployment
make create_deployment
make add_sed SED=test_mass_brdcst SCEWL_ID=161 NAME=mass_brdcst_1 CUSTOM='"LEN=32 SHIFT=0"'
make add_sed SED=test_mass_brdcst SCEWL_ID=162 NAME=mass_brdcst_2 CUSTOM='"LEN=32 SHIFT=1"'
make add_sed SED=test_mass_brdcst SCEWL_ID=163 NAME=mass_brdcst_3 CUSTOM='"LEN=32 SHIFT=2"'
make add_sed SED=test_mass_brdcst SCEWL_ID=164 NAME=mass_brdcst_4 CUSTOM='"LEN=32 SHIFT=3"'
make add_sed SED=test_mass_brdcst SCEWL_ID=165 NAME=mass_brdcst_5 CUSTOM='"LEN=32 SHIFT=4"'
make add_sed SED=test_mass_brdcst SCEWL_ID=166 NAME=mass_brdcst_6 CUSTOM='"LEN=32 SHIFT=5"'
make add_sed SED=test_mass_brdcst SCEWL_ID=167 NAME=mass_brdcst_7 CUSTOM='"LEN=32 SHIFT=6"'
make add_sed SED=test_mass_brdcst SCEWL_ID=168 NAME=mass_brdcst_8 CUSTOM='"LEN=32 SHIFT=7"'

# launch deployment
make deploy

# launch transceiver in background
python3 tools/faa.py $SOCK_ROOT/$FAA_SOCK &

# launch seds detatched
make launch_sed_d NAME=mass_brdcst_1 SCEWL_ID=161
make launch_sed_d NAME=mass_brdcst_2 SCEWL_ID=162
make launch_sed_d NAME=mass_brdcst_3 SCEWL_ID=163
make launch_sed_d NAME=mass_brdcst_4 SCEWL_ID=164
make launch_sed_d NAME=mass_brdcst_5 SCEWL_ID=165
make launch_sed_d NAME=mass_brdcst_6 SCEWL_ID=166
make launch_sed_d NAME=mass_brdcst_7 SCEWL_ID=167
make launch_sed_d NAME=mass_brdcst_8 SCEWL_ID=168

# bring transceiver back into foreground
fg

echo "Killing docker containers..."
docker kill $(docker ps -q) 2>/dev/null
