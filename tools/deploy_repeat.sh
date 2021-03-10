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
export START_ID=10
export END_ID=266
export SC_PROBE_SOCK=sc_probe.sock
export SC_RECVR_SOCK=sc_recvr.sock

# create deployment
make create_deployment
make add_sed SED=echo_server SCEWL_ID=10 NAME=echo_server
make add_sed SED=echo_client SCEWL_ID=11 NAME=echo_client CUSTOM='TGT_ID=10'
make add_sed SED=echo_client SCEWL_ID=12 NAME=echo_client CUSTOM='TGT_ID=10'
make add_sed SED=echo_client SCEWL_ID=13 NAME=echo_client CUSTOM='TGT_ID=10'
make add_sed SED=echo_client SCEWL_ID=14 NAME=echo_client CUSTOM='TGT_ID=10'
make add_sed SED=echo_client SCEWL_ID=15 NAME=echo_client CUSTOM='TGT_ID=10'
make add_sed SED=echo_client SCEWL_ID=16 NAME=echo_client CUSTOM='TGT_ID=10'
#make add_sed SED=echo_client SCEWL_ID=17 NAME=echo_client CUSTOM='TGT_ID=10'
#make add_sed SED=echo_client SCEWL_ID=18 NAME=echo_client CUSTOM='TGT_ID=10'
#make add_sed SED=echo_client SCEWL_ID=19 NAME=echo_client CUSTOM='TGT_ID=10'
#make add_sed SED=echo_client SCEWL_ID=20 NAME=echo_client CUSTOM='TGT_ID=10'
#make add_sed SED=echo_client SCEWL_ID=21 NAME=echo_client CUSTOM='TGT_ID=10'
#make add_sed SED=echo_client SCEWL_ID=22 NAME=echo_client CUSTOM='TGT_ID=10'
#make add_sed SED=echo_client SCEWL_ID=23 NAME=echo_client CUSTOM='TGT_ID=10'
#make add_sed SED=echo_client SCEWL_ID=24 NAME=echo_client CUSTOM='TGT_ID=10'
#make add_sed SED=echo_client SCEWL_ID=25 NAME=echo_client CUSTOM='TGT_ID=10'

# launch deployment
make deploy

# launch transceiver in background
python3 tools/faa.py $SOCK_ROOT/$FAA_SOCK &

# launch seds detatched
make launch_sed_d NAME=echo_server SCEWL_ID=10
sleep 1
make launch_sed_d NAME=echo_client SCEWL_ID=11
make launch_sed_d NAME=echo_client SCEWL_ID=12
make launch_sed_d NAME=echo_client SCEWL_ID=13
make launch_sed_d NAME=echo_client SCEWL_ID=14
make launch_sed_d NAME=echo_client SCEWL_ID=15
make launch_sed_d NAME=echo_client SCEWL_ID=16
#make launch_sed_d NAME=echo_client SCEWL_ID=17
#make launch_sed_d NAME=echo_client SCEWL_ID=18
#make launch_sed_d NAME=echo_client SCEWL_ID=19
#make launch_sed_d NAME=echo_client SCEWL_ID=20
#make launch_sed_d NAME=echo_client SCEWL_ID=21
#make launch_sed_d NAME=echo_client SCEWL_ID=22
#make launch_sed_d NAME=echo_client SCEWL_ID=23
#make launch_sed_d NAME=echo_client SCEWL_ID=24
#make launch_sed_d NAME=echo_client SCEWL_ID=25
sleep 100
make launch_sed_d NAME=echo_client SCEWL_ID=12
make launch_sed_d NAME=echo_client SCEWL_ID=13
make launch_sed_d NAME=echo_client SCEWL_ID=14
make launch_sed_d NAME=echo_client SCEWL_ID=15
make launch_sed_d NAME=echo_client SCEWL_ID=16


# bring transceiver back into foreground
fg

echo "Killing docker containers..."
docker kill $(docker ps -q) 2>/dev/null
