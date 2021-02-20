/*
 * MITRE 2021 Collegiate eCTF
 * SCEWL Bus Controller header
 * 
 * 0xDACC
 * Adrian Self
 * Delaware Area Career Center
 *
 * This source file is part of our design for MITRE's 2021 Embedded System CTF (eCTF).
 * It documents and declares the secure networking capabilities of the SCEWL Bus Controller.
 */


#ifndef CONTROLLER_H
#define CONTROLLER_H

#include "interface.h"
#include "lm3s/lm3s_cmsis.h"

#include <stdint.h>
#include <string.h>

#define SCEWL_MAX_DATA_SZ 0x4000

// type of a SCEWL ID
typedef uint16_t scewl_id_t;

// SCEWL_ID must be defined
#ifndef SCEWL_ID
#error "SCEWL_ID not defined"
#endif

// Network-layer header struct (112 bytes)
typedef struct __attribute__((__packed__)) secure_hdr_t {
  uint8_t sig[64];  //ECDSA signature
  uint16_t src;     //src and tgt are depl_id's, not SCEWL_ID's
  uint16_t tgt;
  uint64_t seq;     //64-bit sequence number
  uint16_t ctlen;
  uint16_t padding;
  uint8_t key[16];  //128-bit encrypted AES key
  uint8_t iv[16];
  /* ciphertext follows */
} secure_hdr_t;

// SCEWL bus channel header
// NOTE: This is the required format to comply with Section 4.6 of the rules
typedef struct scewl_hdr_t {
  uint8_t magicS;  // all messages must start with the magic code "SC"
  uint8_t magicC;
  scewl_id_t tgt_id;
  scewl_id_t src_id;
  uint16_t len;
  /* data follows */
} scewl_hdr_t;

// registration message
typedef struct scewl_sss_msg_t {
  scewl_id_t dev_id;
  uint16_t   op;
} scewl_sss_msg_t;

// SCEWL status codes
enum scewl_status 
#define SCEWL_ERR 0
#define SCEWL_NO_MSG 0
#define SCEWL_OK 1
//TODO #define SCEWL_ALREADY

// registration/deregistration options
enum scewl_sss_op_t { SCEWL_SSS_ALREADY = -1, SCEWL_SSS_REG, SCEWL_SSS_DEREG };

// reserved SCEWL IDs
enum scewl_ids { SCEWL_BRDCST_ID, SCEWL_SSS_ID, SCEWL_FAA_ID };

/*
 * read_msg
 *
 * Gets a message in the SCEWL frame format from an interface
 *
 * Args:
 *   [in]  intf - pointer to the physical interface device
 *   [in]  buf - pointer to the message buffer
 *   [out] src_id - pointer to a src_id
 *   [out] tgt_id - pointer to a tgt_id
 *   [in]  n - maximum characters to be read into buf
 *   [in]  blocking - whether to wait for a message or not
 * Returns:
 *   On success, the number of bytes read.
 *   If no frame was successfully read, SCEWL_NO_MSG.
 */
int read_msg(intf_t *intf, char *buf, scewl_id_t *src_id, scewl_id_t *tgt_id,
             size_t n, int blocking);

/*
 * send_msg
 * 
 * Sends a message in the SCEWL frame format to an interface
 * 
 * Args:
 *   [in]  intf - pointer to the physical interface device
 *   [in]  src_id - the id of the sending device
 *   [in]  tgt_id - the id of the receiving device
 *   [in]  len - the length of message
 *   [in]  data - pointer to the message
 * Returns:
 *   SCEWL_OK always
 */
int send_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data);

/*
 * secure_direct_recv
 * 
 * Interprets a SCEWL direct tranmission from another SED,
 * verifying the network packet's authenticity and integrity
 * and decrypting the message contents.
 * The sequence number is recorded to prevent replay, then
 * the message is sent to the CPU in a SCEWL frame.
 *
 * Args:
 *   [in]  data - pointer to incoming network packet
 *   [in]  src_scewl_id - the id of the sending device
 *   [in]  len - the length of the network packet
 * Returns:
 *   On success, SCEWL_OK.
 *   On failure, SCEWL_ERR.
 *     -bad length
 *     -bad source
 *     -bad signature
 *     -expired (low seq number)
 *     -internal error
 */
int secure_direct_recv(char* data, scewl_id_t src_scewl_id, uint16_t len);

/*
 * secure_direct_send
 * 
 * Sends a direct transmission to another SED from the CPU,
 * encrypting and signing the message and encapsulating it
 * into a network packet then into a SCEWL frame.
 * A sequence number is used so that packets may be ordered.
 *
 * Args:
 *   [in]  data - pointer to message contents
 *   [in]  tgt_scewl_id - the id of the target device
 *   [in]  len - the length of the message
 * Returns:
 *   On success, SCEWL_OK.
 *   On failure, SCEWL_ERR.
 *     -bad length
 *     -bad target
 *     -internal error
 */
int secure_direct_send(char* data, scewl_id_t tgt_scewl_id, uint16_t len);

/*
 * handle_brdcst_recv
 * 
 * Interprets a broadcast message from another SED and passes it to the CPU
 */
int handle_brdcst_recv(char* data, scewl_id_t src_id, uint16_t len);

/*
 * handle_brdcst_send
 * 
 * Broadcasts a message from the CPU to SEDS over the antenna
 */
int handle_brdcst_send(char *data, uint16_t len);

/*
 * handle_faa_recv
 * 
 * Receives an FAA message from the antenna and passes it to the CPU
 *
 * Args:
 *   [in]  data - pointer to FAA message contents
 *   [in]  len - length of FAA message
 * Returns:
 *   SCEWL_OK always
 */
int handle_faa_recv(char* data, uint16_t len);

/*
 * handle_faa_send
 * 
 * Sends an FAA message from the CPU to the antenna
 *
 * Args:
 *   [in]  data - pointer to FAA message contents
 *   [in]  len - length of FAA message
 * Returns:
 *   SCEWL_OK always
 */
int handle_faa_send(char* data, uint16_t len);

/*
 * handle_registration
 * 
 * Interprets a CPU registration message
 * 
 * args:
 *   op - pointer to the operation message received by the CPU
 */
int handle_registration(char* op);

/*
 * sss_register
 * 
 * Performs a registration with the SSS
 */
int sss_register();

/*
 * sss_deregister
 * 
 * Performs a deregistration with the SSS
 */
int sss_deregister();


#endif

