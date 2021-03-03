# 2021 MITRE eCTF Challenge: Secure Common Embedded Wireless Link (SCEWL) by 0xDACC
This repository implements our team's design for MITRE's 2021 Embedded 
System CTF (eCTF). This code was designed with security in mind,
preparing for the attack phase in which opposing teams will
attempt to exploit our design.

## Documentation
Make sure to check out the documentation.
Our SCEWL Bus Controller code is documented in [controller.h](controller/controller.h), including the structs used for various communications.
Our high-level Design Document is also available at [Design Document](Design_Document.pdf).

## Getting Started
Please see the [Getting Started Guide](getting_started.md).

Also see the distributed documentation for a guide to the design and
features of this code.

## Project Structure
The project code is structured as follows

* `controller/` - Contains everything to build the SCEWL Bus Controller. See [Controller README](controller/README.md)
* `cpu/` - Contains everything to build the user code of the CPU. See [CPU README](cpu/README.md)
* `dockerfiles/` - Contains all Dockerfiles to build system
* `radio/` - Contains the Radio Waves Emulator
* `socks/` - Directory to hold sockets for the network backend
* `sss/` - Contains the Scewl Security Server and a deployment helper program
* `tools/` - Miscellaneous tools to run and interract with deployments
* `Makefile` - Root Makefile to build deployments
