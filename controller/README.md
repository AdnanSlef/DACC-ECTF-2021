# 0xDACC SCEWL Bus Controller
The SCEWL Bus Controller implements the security and functionality of the SCEWL
protocol and is one of two components our team had to implement (the other being
the SSS in `/sss/`). The SCEWL Bus Controller runs on a Stellaris lm3s6965 chip,
which will be emulated using qemu-system-arm.

The SCEWL Bus Controller is built from several files:

* `controller.{c,h}`: Implements the main functionality of the SCEWL Bus
  Controller. It contains `main()` and handles the message passing of the system
* `interface.{c,h}`: Implements the interface to the hardware interfaces, reading
  and writing raw bytes. Our design uses the reference `interface.{c,h}` code.
* `lm3s/`: Contains files to help interface with the lm3s6965 chip. Our design uses
  the reference `lm3s/` code.
* `lm3s/startup_gcc.c`: Implements the system startup code, including initializing the
  stack and reset vectors. Our design uses the reference `startup_gcc.c`.
* `lm3s/controller.ld`: The linker script to set up memory regions. Our design modifies
  the reference `controller.ld`.
* `CMSIS/`: Contains files to help interface with the ARM Cortex-M3 proccessor.
  Our design uses the reference `CMSIS/` code.
* `sed.secret.h`: Contains secrets specific to each SED's controller. Generated by
  `2c_build_controller.Dockerfile` during the `make add_sed` command. Deleted after
  build is performed.

Documentation for the Controller is found in `controller.h`.

## Crypto Libraries
Our design relies on a number of crypto libraries to provide cryptographic functionality.
These are included as submodules.

* `sweet-b/`: Provides ECDH and ECDSA functionality, along with SHA-256 and HMAC\_DRBG. From https://github.com/westerndigitalcorporation/sweet-b
* `tiny-AES-c/`: Provides AES functionality, and implements CTR and CBC (no padding provided) modes. From https://github.com/kokke/tiny-AES-c.
