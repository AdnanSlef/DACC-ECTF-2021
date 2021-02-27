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
#define DEPL_COUNT 256

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
  uint16_t ctlen;
  uint16_t padding;
  uint64_t seq;     //64-bit sequence number
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

// basic registration message
typedef struct scewl_sss_msg_t {
  scewl_id_t dev_id;
  uint16_t   op;
} scewl_sss_msg_t;

// registration request message
typedef struct sss_reg_req_t {
  scewl_sss_msg_t basic;
} sss_reg_req_t;

// deregistration request message
typedef struct sss_dereg_req_t {
  scewl_sss_msg_t basic;
} sss_dereg_req_t;

// registration response message
typedef struct sss_reg_rsp_t {
  scewl_sss_msg_t basic;
  uint32_t padding;
  uint16_t ids_db[DEPL_COUNT];     //maps SCEWL ids to deployment ids
  uint64_t seq;                    //this SED's sequence number
  uint64_t known_seqs[DEPL_COUNT]; //last-seen seq numbers
  uint8_t  cryptkey[16]; //key to unlock ecc
  uint8_t  cryptiv[16];  //iv to unlock ecc
  uint8_t  entropky[16]; //just random data
  uint8_t  entriv[16];   //"              "
} sss_reg_rsp_t;

// deregistration response message
typedef struct sss_dereg_rsp_t {
  scewl_sss_msg_t basic;
} sss_dereg_rsp_t;

// SCEWL status codes
#define SCEWL_ERR 0
#define SCEWL_NO_MSG 0
#define SCEWL_OK 1

// registration/deregistration options
enum scewl_sss_op_t { SCEWL_SSS_ALREADY = -1, SCEWL_SSS_REG, SCEWL_SSS_DEREG };

// reserved SCEWL IDs
enum scewl_ids { SCEWL_BRDCST_ID, SCEWL_SSS_ID, SCEWL_FAA_ID };

/*
 * l2_filter
 *
 * Filters SCEWL frames read from an interface
 *
 * Args:
 *   [in]  intf - pointer to the physical interface device
 *   [in]  src_id - SCEWL ID from which the frame purports to be sent
 *   [in]  tgt_id - SCEWL ID being targeted
 *
 * Returns:
 *   SCEWL_OK if the frame should be processed.
 *   SCEWL_ERR if the frame should be ignored.
 */
_Bool l2_filter(intf_t * intf, scewl_id_t src_id, scewl_id_t tgt_id);

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
 * secure_recv
 * 
 * Interprets a SCEWL tranmission from another SED,
 * verifying the network packet's authenticity and integrity
 * and decrypting the message contents.
 * The sequence number is recorded to prevent replay, then
 * the message is sent to the CPU in a SCEWL frame.
 *
 * Args:
 *   [in]  data - pointer to incoming network packet
 *   [in]  src_scewl_id - the id of the sending device
 *   [in]  len - the length of the network packet
 *   [in]  broadcast - whether the received frame was a broadcast
 * Returns:
 *   On success, SCEWL_OK.
 *   On failure, SCEWL_ERR.
 *     -bad length
 *     -bad source
 *     -bad signature
 *     -expired (low seq number)
 *     -internal error
 */
int secure_recv(char* data, scewl_id_t src_scewl_id, uint16_t len, _Bool broadcast);

/*
 * secure_send
 * 
 * Sends a transmission to another SED from the CPU,
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
int secure_send(char* data, scewl_id_t tgt_scewl_id, uint16_t len);

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

/*
 * prep_drbg
 *
 * Attempts to reseed the CSPRNG if necessary
 *
 */
void prep_drbg(void);

#endif

