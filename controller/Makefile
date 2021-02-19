#  2021 Collegiate eCTF
#  SCEWL Bus Controller Makefile
#  Ben Janis
#
#  (c) 2021 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!


# define the part type and base directory - must be defined for makedefs to work
PART=LM3S6965
ROOT=.

# include the common make definitions
include lm3s/makedefs

# add additional directories to search for source files to VPATH
VPATH=lm3s

# add additional directories to search for header files to IPATH
IPATH=${ROOT}
IPATH+=${ROOT}/CMSIS/Include
IPATH+=${VPATH}

# add flags to pass to the compiler
CFLAGS+=-DSCEWL_ID=${SCEWL_ID}

# this rule must come first in `all`
all: ${COMPILER}

# for each source file that needs to be compiled besides
# the file that defines `main`, add the next two lines 
LDFLAGS+=${COMPILER}/interface.o
all: ${COMPILER}/interface.o

################ start aes inclusion ################
# example AES rules to build in tiny-AES-c: https://github.com/kokke/tiny-AES-c
# make sure submodule has been pulled (run `git submodule update --init`)
# uncomment next line to activate
DO_MAKE_TINY_AES=yes
ifdef DO_MAKE_TINY_AES
# path to aes library
AESPATH=./tiny-AES-c

# add path to aes source files to source path
VPATH+=${AESPATH}

# add aes library to includes path
IPATH+=${AESPATH}

# add aes object file to includes path
LDFLAGS+=${COMPILER}/aes.o

# add compiler flag to enable test AES code 
CFLAGS+=-DTEST_AES

# add rule to build aes library
all: ${COMPILER}/aes.o
endif
################# end aes inclusion #################


################ start uECC inclusion ################
DO_MAKE_MICRO_ECC=yes
ifdef DO_MAKE_MICRO_ECC

# path to uECC library
UECCPATH=./micro-ecc

# add path to uECC source files to source path
VPATH+=${UECCPATH}

# add uECC library to includes path
IPATH+=${UECCPATH}

# add uECC object file to includes path
LDFLAGS+=${COMPILER}/uECC.o

# add compiler flag to enable test uECC code
CFLAGS+=-DTEST_ECC

# add rule to build uECC library
all: ${COMPILER}/uECC.o
endif
################# end uECC inclusion #################


################ start sweet-b inclusion ################
DO_MAKE_SWEET_B=yes
ifdef DO_MAKE_SWEET_B

# path to sweet-b library
SBPATH=./sweet-b

# add path to sweet-b source files to source path
VPATH+=${SBPATH}/src
VPATH+=${SBPATH}/include

# add sweet-b library to includes path
IPATH+=${SBPATH}/include
IPATH+=${SBPATH}/src

# add compiler flag to enable test ECC (B) code
CFLAGS+=-DTEST_ECC_B

# add compiler flag to allow sweet-b to work on Cortex-M3
CFLAGS+=-DSB_WORD_SIZE=2

# disable the unused curve
CFLAGS+=-DSB_SW_SECP256K1_SUPPORT=0

# add sweet-b object files to includes path
LDFLAGS+=${COMPILER}/sb_sha256.o
LDFLAGS+=${COMPILER}/sb_fe.o
LDFLAGS+=${COMPILER}/sb_hmac_sha256.o
LDFLAGS+=${COMPILER}/sb_hmac_drbg.o
LDFLAGS+=${COMPILER}/sb_hkdf.o
LDFLAGS+=${COMPILER}/sb_sw_lib.o

# add rules to build sweet-b components
all: ${COMPILER}/sb_sha256.o
all: ${COMPILER}/sb_fe.o
all: ${COMPILER}/sb_hmac_sha256.o
all: ${COMPILER}/sb_hmac_drbg.o
all: ${COMPILER}/sb_hkdf.o
all: ${COMPILER}/sb_sw_lib.o

endif
################# end sweet-b inclusion #################

# Show memory usage (TODO remove)
LDFLAGS+=--print-memory-usage
CFLAGS+=-fstack-usage
CFLAGS+=-fdump-tree-optimized
CFLAGS+=-Wstack-usage=1000

# this must be the last build rule of `all`
all: ${COMPILER}/controller.axf

# clean all build products
clean:
	@rm -rf ${COMPILER} ${wildcard *~}

# create the output directory
${COMPILER}:
	@mkdir ${COMPILER}

# check that SCEWL_ID is defined
check_defined = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined,$1)))
__check_defined = \
    $(if $(value $1),, \
      $(error Undefined $1))
arg_check:
	$(call check_defined, SCEWL_ID)

${COMPILER}/controller.axf: arg_check
${COMPILER}/controller.axf: ${COMPILER}/controller.o
${COMPILER}/controller.axf: ${COMPILER}/startup_${COMPILER}.o
${COMPILER}/controller.axf: ${COMPILER}/system_lm3s.o
ifeq (${COMPILER}, gcc)
${COMPILER}/controller.axf: lm3s/controller.ld
endif
SCATTERgcc_controller=lm3s/controller.ld
ifeq (${COMPILER}, sourcerygxx)
${COMPILER}/controller.axf: controller_sourcerygxx.ld
endif
SCATTERsourcerygxx_controller=lm3s6965-rom.ld -T controller_sourcerygxx.ld
ENTRY_controller=Reset_Handler

#
# Include the automatically generated dependency files.
#
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${COMPILER}/*.d} __dummy__
endif
