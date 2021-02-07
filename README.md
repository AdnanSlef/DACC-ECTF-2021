# 2021 MITRE eCTF Challenge: Secure Common Embedded Wireless Link (SCEWL)
This repository implements a design for MITRE's 2021 Embedded 
System CTF (eCTF). This code was designed with security in mind,
preparing for the attack phase in which opposing teams will
attempt to exploit our design.

## Getting Started
Please see the [Getting Started Guide](getting_started.md).

Also see the distributed walkthrough slides for a guide to working with and
running this code.

## Project Structure
The example code is structured as follows

* `controller/` - Contains everything to build the SCEWL Bus Controller. See [Controller README](controller/README.md)
* `cpu/` - Contains everything to build the user code of the CPU. See [CPU README](cpu/README.md)
* `dockerfiles/` - Contains all Dockerfiles to build system
* `radio/` - Contains the Radio Waves Emulator
* `socks/` - Directory to hold sockets for the network backend
* `sss/` - Contains the Scewl Security Server and a deployment helper program
* `tools/` - Miscellaneous tools to run and interract with deployments
* `Makefile` - Root Makefile to build deployments
