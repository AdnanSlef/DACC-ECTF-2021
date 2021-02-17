/*
 * 2021 Collegiate eCTF
 * SCEWL Bus Controller implementation
 * Ben Janis
 *
 * (c) 2021 The MITRE Corporation
 *
 * This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 */

#include "controller.h"
#include "sed.secret.h"

#ifdef TEST_AES
#include "aes.h"
#endif

#ifdef TEST_ECC
#include "uECC.h"
#endif

#ifdef TEST_ECC_B
#include "sb_all.h"
#endif

#define debug_str(M) send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, strlen(M), M)

// message buffer
char buf[SCEWL_MAX_DATA_SZ];

int unsafe_test_rng(uint8_t *dest, unsigned int size);//TODO remove

void bxor(uint8_t *buf, const uint8_t *key, uint16_t len)
{
  uint16_t i;
  for (i = 0; i < len; i++) {
    buf[i] ^= key[i];
  }
}

void bcopy(uint8_t *dst, const uint8_t *src, uint16_t len)
{
  while (0 != len) {
    len--;
    dst[len] = src[len];
  }
}

int read_msg(intf_t *intf, char *data, scewl_id_t *src_id, scewl_id_t *tgt_id,
             size_t n, int blocking) {
  scewl_hdr_t hdr;
  int read, max;

  do {
    // clear buffer and header
    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, n);

    // find header start
    do {
      hdr.magicC = 0;

      if (intf_read(intf, (char *)&hdr.magicS, 1, blocking) == INTF_NO_DATA) {
        return SCEWL_NO_MSG;
      }

      // check for SC
      if (hdr.magicS == 'S') {
        do {
          if (intf_read(intf, (char *)&hdr.magicC, 1, blocking) == INTF_NO_DATA) {
            return SCEWL_NO_MSG;
          }
        } while (hdr.magicC == 'S'); // in case of multiple 'S's in a row
      }
    } while (hdr.magicS != 'S' && hdr.magicC != 'C');

    // read rest of header
    read = intf_read(intf, (char *)&hdr + 2, sizeof(scewl_hdr_t) - 2, blocking);
    if(read == INTF_NO_DATA) {
      return SCEWL_NO_MSG;
    }

    // unpack header
    *src_id = hdr.src_id;
    *tgt_id = hdr.tgt_id;

    // read body
    max = hdr.len < n ? hdr.len : n;
    read = intf_read(intf, data, max, blocking);

    // throw away rest of message if too long
    for (int i = 0; hdr.len > max && i < hdr.len - max; i++) {
      intf_readb(intf, 0);
    }

    // report if not blocking and full message not received
    if(read == INTF_NO_DATA || read < max) {
      return SCEWL_NO_MSG;
    }

  } while (intf != CPU_INTF && intf != SSS_INTF &&                       // always valid if from CPU or SSS
           ((hdr.tgt_id == SCEWL_BRDCST_ID && hdr.src_id == SCEWL_ID) || // ignore own broadcast
            (hdr.tgt_id != SCEWL_BRDCST_ID && hdr.tgt_id != SCEWL_ID))); // ignore direct message to other device

  return max;
}


int send_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data) {
  scewl_hdr_t hdr;

  // pack header
  hdr.magicS = 'S';
  hdr.magicC = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len    = len;

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  intf_write(intf, data, len);

  return SCEWL_OK;
}


int handle_scewl_recv(char* data, scewl_id_t src_id, uint16_t len) {
  struct AES_ctx ctx;
  uint8_t key[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
  uint8_t iv[16] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0 };
  
  // initialize context
  AES_init_ctx_iv(&ctx, key, iv);
  
  // decrypt buffer (decryption happens in place)
  AES_CTR_xcrypt_buffer(&ctx, data, len); //TODO watch for Defense in Depth

  return send_msg(CPU_INTF, src_id, SCEWL_ID, len, data);
}

int handle_scewl_send(char* data, scewl_id_t tgt_id, uint16_t len) {
  struct AES_ctx ctx;
  uint8_t key[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
  uint8_t iv[16] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0 };
  
  // initialize context
  AES_init_ctx_iv(&ctx, key, iv);

  // encrypt buffer (encryption happens in place)
  AES_CTR_xcrypt_buffer(&ctx, data, len);

  return send_msg(RAD_INTF, SCEWL_ID, tgt_id, len, data);
}

int handle_scewl_send_secured(char* data, scewl_id_t tgt_id, uint16_t len) {
  scewl_hdr_t frame_hdr;
  secure_hdr_t packet_hdr;
  uint16_t depl_tgt = !DEPL_ID; //only works in 2-SED mode (TODO use lookup table)
  uint8_t ss[32]; //shared secret
  struct AES_ctx ctx;
  uint8_t key[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf }; //TODO random
  uint8_t iv[16] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0 }; //TODO random
  struct uECC_Curve_t *curve = uECC_secp256r1();
  
  // establish shared secret
  uECC_set_rng(&unsafe_test_rng);//TODO use CSPRNG
  if (!uECC_shared_secret(ECC_PUBLICS_DB[depl_tgt], ECC_PRIVATE_KEY, ss, curve)) {
    return SCEWL_ERR;
  }

  // simple key derivation function
  //TODO ss = hash(raw_ss);

  // initialize context
  AES_init_ctx_iv(&ctx, key, iv);

  // encrypt buffer (encryption happens in place)
  AES_CTR_xcrypt_buffer(&ctx, data, len); //TODO check Defense in Depth
  
  // encrypt key with shared secret
  bxor(key, ss, 16);

  // pack packet header
  packet_hdr.src = DEPL_ID;
  packet_hdr.tgt = depl_tgt;
  packet_hdr.seq = seq++;
  packet_hdr.ctlen = len;
  bcopy(packet_hdr.key, key, 16);
  bcopy(packet_hdr.iv, iv, 16);

  // sign the packet
  //TODO eccsigbuf = sign(packet)
  //TODO bcopy(packet_hdr.sig, eccsigbuf, 64);
  
  // pack frame header
  frame_hdr.magicS = 'S';
  frame_hdr.magicC = 'C';
  frame_hdr.src_id = SCEWL_ID;
  frame_hdr.tgt_id = tgt_id;
  frame_hdr.len    = sizeof(packet_hdr) + packet_hdr.ctlen;

  // send frame header
  intf_write(RAD_INTF, (char *)&frame_hdr, sizeof(scewl_hdr_t));

  // send packet header
  intf_write(RAD_INTF, (char *)&packet_hdr, sizeof(secure_hdr_t));

  // send ciphertext
  intf_write(RAD_INTF, data, len);

  return SCEWL_OK;
}


int handle_brdcst_recv(char* data, scewl_id_t src_id, uint16_t len) {
  return send_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data);
}


int handle_brdcst_send(char *data, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_BRDCST_ID, len, data);
}   


// left unmodified to comply with FAA specifications
int handle_faa_recv(char* data, uint16_t len) {
  return send_msg(CPU_INTF, SCEWL_FAA_ID, SCEWL_ID, len, data);
}

// left unmodified to comply with FAA specifications
int handle_faa_send(char* data, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, data);
}


int handle_registration(char* msg) {
  scewl_sss_msg_t *sss_msg = (scewl_sss_msg_t *)msg;
  if (sss_msg->op == SCEWL_SSS_REG) {
    return sss_register();
  }
  else if (sss_msg->op == SCEWL_SSS_DEREG) {
    return sss_deregister();
  }

  // bad op
  return 0;
}


int sss_register() {
  scewl_sss_msg_t msg;
  scewl_id_t src_id, tgt_id;
  int status, len;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_REG;
  
  // send registration
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // receive response
  len = read_msg(SSS_INTF, (char *)&msg, &src_id, &tgt_id, sizeof(scewl_sss_msg_t), 1);

  // notify CPU of response
  status = send_msg(CPU_INTF, src_id, tgt_id, len, (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // op should be REG on success
  return msg.op == SCEWL_SSS_REG;
}


int sss_deregister() {
  scewl_sss_msg_t msg;
  scewl_id_t src_id, tgt_id;
  int status, len;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_DEREG;
  
  // send registration
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // receive response
  len = read_msg(SSS_INTF, (char *)&msg, &src_id, &tgt_id, sizeof(scewl_sss_msg_t), 1);

  // notify CPU of response
  status = send_msg(CPU_INTF, src_id, tgt_id, len, (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // op should be DEREG on success
  return msg.op == SCEWL_SSS_DEREG;
}

#ifdef TEST_AES
void test_aes() {

  // example encryption using tiny-AES-c
  struct AES_ctx ctx;
  uint8_t key[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
  uint8_t iv[16] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0 };
  uint8_t plaintext[0x4020] = "A123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeZ";

  // initialize context
  AES_init_ctx_iv(&ctx, key, iv);

  // encrypt buffer (encryption happens in place)
  AES_CBC_encrypt_buffer(&ctx, plaintext, 0x4000);
  debug_str("Example encrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 0x4000, (char *)plaintext);

  AES_ctx_set_iv(&ctx, iv); //encryption just mangled ctx.Iv; fix it.

  // decrypt buffer (decryption happens in place)
  AES_CBC_decrypt_buffer(&ctx, plaintext, 0x4000);
  debug_str("Example decrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 0x4000, (char *)plaintext);
  // end example
}
#endif

//Numerical Recipes LCG, take 2nd-most significant byte
int unsafe_rng_counter = 0xdeadbeef; //RNG Seed will come from SSS
int unsafe_test_rng(uint8_t *dest, unsigned int size) {
  
  while (size) {
    unsafe_rng_counter *= 1664525;
    unsafe_rng_counter += 1013904223;
    
    *dest = ((uint8_t *)&unsafe_rng_counter)[2];

    dest++;
    size--;
  }
  return 1;
}

void test_ecc() {
  uint8_t private1[32] = {0};
  uint8_t private2[32] = {0};
  uint8_t public1[64] = {0};
  uint8_t public2[64] = {0};
  uint8_t secret1[32] = {0};
  uint8_t secret2[32] = {0};

  // Define the ECC curve here
  const struct uECC_Curve_t *curve = uECC_secp256r1();

  uECC_set_rng(&unsafe_test_rng);

  if (!uECC_make_key(public1, private1, curve) ||
      !uECC_make_key(public2, private2, curve))
  {
    debug_str("uECC_make_key() failed");
    return;
  }

  if (!uECC_shared_secret(public2, private1, secret1, curve)) {
    debug_str("shared_secret() call 1 failed");
    return;
  }

  if (!uECC_shared_secret(public1, private2, secret2, curve)) {
    debug_str("shared_secret() call 2 failed");
    return;
  }

  //debug the shared secrets; they should match
  debug_str("Shared secrets 1 and 2:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 32, secret1);
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 32, secret2);

  debug_str("Public keys 1 and 2:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 64, public1);
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 64, public2);

  debug_str("Private keys 1 and 2:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 32, private1);
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 32, private2);
}

void test_ecc2(void)
{
  /*    Test ECDH    */
  uint16_t other = !DEPL_ID;
  uint8_t secret[32] = {0};
  const struct uECC_Curve_t *curve = uECC_secp256r1();
  
  uECC_set_rng(&unsafe_test_rng);

  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (uint8_t *)&other);
  if (!uECC_shared_secret(ECC_PUBLICS_DB[other], ECC_PRIVATE_KEY, secret, curve)) {
    debug_str("shared_secret() call failed");
    return;
  }

  //debug the shared secrets; they should match
  debug_str("My private key:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 32, ECC_PRIVATE_KEY);
  
  debug_str("Other's public key:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 64, ECC_PUBLICS_DB[other]);
  
  debug_str("Shared secret:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 32, secret);
  /******************/

  /*   Test ECDSA    */
  uint8_t message[32];
  uint8_t hash[32];
  bcopy(message,secret,32);
  bcopy(hash,message,32);//TODO hash = sha256(message);
  uint8_t signature[64];

  uECC_sign(ECC_PRIVATE_KEY, hash, 32, signature, curve);

  debug_str("ECDSA sig:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 64, signature);

  debug_str(
    uECC_verify(ECC_PUBLICS_DB[DEPL_ID], hash, 32, signature, curve)
    ? "Signature correct" : "Signature invalid"
  );
  /*******************/
}

void test_eccb(void)
{
  /*    Test ECDH    */
  uint16_t other = !DEPL_ID;
  uint8_t secret[32] = {0};
  const struct uECC_Curve_t *curve = uECC_secp256r1();
  
  uECC_set_rng(&unsafe_test_rng);

  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (uint8_t *)&other);
  if (!uECC_shared_secret(ECC_PUBLICS_DB[other], ECC_PRIVATE_KEY, secret, curve)) {
    debug_str("shared_secret() call failed");
    return;
  }

  //debug the shared secrets; they should match
  debug_str("My private key:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 32, ECC_PRIVATE_KEY);
  
  debug_str("Other's public key:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 64, ECC_PUBLICS_DB[other]);
  
  debug_str("Shared secret:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 32, secret);
  /******************/

  /*   Test ECDSA    */
  uint8_t *message = "abc";
  uint8_t hash[SB_SHA256_SIZE];
  sb_sha256_state_t ctx;

  sb_sha256_message(&ctx, hash, message, 3); //only abc, not \0
  
  debug_str("SHA-256 hash:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, SB_SHA256_SIZE, hash);

  uint8_t signature[64];
  uECC_sign(ECC_PRIVATE_KEY, hash, 32, signature, curve);

  debug_str("ECDSA sig:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 64, signature);

  debug_str(
    uECC_verify(ECC_PUBLICS_DB[DEPL_ID], hash, 32, signature, curve)
    ? "Signature correct" : "Signature invalid"
  );
  /*******************/
}

void test_drbg()
{
  /*    instantiate drbg    */
  sb_hmac_drbg_state_t drbg;
  uint8_t entropy[32] = { 0xca, 0x85, 0x19, 0x11, 0x34, 0x93, 0x84, 0xbf, 0xfe, 0x89, 0xde, 0x1c, 0xbd, 0xc4, 0x6e, 0x68, 0x31, 0xe4, 0x4d, 0x34, 0xa4, 0xfb, 0x93, 0x5e, 0xe2, 0x85, 0xdd, 0x14, 0xb7, 0x1a, 0x74, 0x88 };
  uint8_t nonce[16] = { 0x65, 0x9b, 0xa9, 0x6c, 0x60, 0x1d, 0xc6, 0x9f, 0xc9, 0x02, 0x94, 0x08, 0x05, 0xec, 0x0c, 0xa8 };

  sb_hmac_drbg_init(&drbg, entropy, 32, nonce, 16, depl_id_str, 8);
  /**************************/

  /*    encrypt a message    */
  struct AES_ctx ctx;
  uint8_t aeskey[16];
  uint8_t iv[16];
  uint8_t data[33] = "A123456789abcdef 123456789abcdeZ"; //plain&cipher text
  int len = 32;
  
  //generate secure randomness for aes
  sb_hmac_drbg_generate(&drbg, aeskey, 16);//TODO reseed
  sb_hmac_drbg_generate(&drbg, iv, 16);

  debug_str("Random aes key and iv:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 16, aeskey);
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 16, iv);

  // initialize AES context
  AES_init_ctx_iv(&ctx, aeskey, iv);

  // encrypt buffer (in-place)
  AES_CTR_xcrypt_buffer(&ctx, data, len);

  debug_str("Ciphertext:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, data);
  /***************************/

  /*    establish shared secret    */
  uint16_t other = !DEPL_ID; //TODO lookup table
  sb_sw_context_t sb_ctx;
  sb_sw_shared_secret_t secret;
  sb_sw_private_t *private = (sb_sw_private_t *)ECC_PRIVATE_KEY;
  sb_sw_public_t *public = (sb_sw_public_t *)ECC_PUBLICS_DB[other];
  sb_hkdf_state_t hkdf;
  uint8_t xorkey[16];

  sb_sw_shared_secret(&sb_ctx, &secret, private, public, &drbg, SB_SW_CURVE_P256, 1);//TODO handle error

  debug_str("Shared secret:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(secret), &secret);
  /*********************************/

  /*    encrypt aes key    */
  sb_hkdf_extract(&hkdf, NULL, 0, &secret, sizeof(secret));
  sb_hkdf_expand(&hkdf, NULL, 0, xorkey, 16);
  bxor(aeskey, xorkey, 16);

  debug_str("Encrypted AES key:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 16, aeskey);
  /*************************/
}

int main() {
  int registered = 0, len;
  scewl_hdr_t hdr;
  uint16_t src_id, tgt_id;

  // initialize interfaces
  intf_init(CPU_INTF);
  intf_init(SSS_INTF);
  intf_init(RAD_INTF);

  /* do  AES test */
  #ifdef TEST_AES
  //test_aes();
  #endif
  /* end AES test */

  /* do  uECC test */
  #ifdef TEST_ECC
  //test_ecc2();
  #endif
  /* end uECC test */

  /* do  sweet-b test */
  #ifdef TEST_ECC_B
  test_eccb();
  test_drbg();
  #endif
  /* end sweet-b test */

  /*   test secrets   */
  debug_str(depl_id_str);
  depl_id_str[1] = 0xd0; //Shows that secrets may be modified
  debug_str(depl_id_str);
  /* end secrets test */

  // serve forever
  while (1) {
    // register with SSS
    read_msg(CPU_INTF, buf, &hdr.src_id, &hdr.tgt_id, sizeof(buf), 1);

    if (hdr.tgt_id == SCEWL_SSS_ID) {
      registered = handle_registration(buf);
    }

    // server while registered
    while (registered) {
      memset(&hdr, 0, sizeof(hdr));

      // handle outgoing message from CPU
      if (intf_avail(CPU_INTF)) {
        // Read message from CPU
        len = read_msg(CPU_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

        if (tgt_id == SCEWL_BRDCST_ID) {
          handle_brdcst_send(buf, len);
        } else if (tgt_id == SCEWL_SSS_ID) {
          registered = handle_registration(buf);
        } else if (tgt_id == SCEWL_FAA_ID) {
          handle_faa_send(buf, len);
        } else {
          handle_scewl_send(buf, tgt_id, len);
        }

        continue;
      }

      // handle incoming radio message
      if (intf_avail(RAD_INTF)) {
        // Read message from antenna
        len = read_msg(RAD_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

        if (tgt_id == SCEWL_BRDCST_ID) {
          handle_brdcst_recv(buf, src_id, len);
        } else if (src_id == SCEWL_FAA_ID) {
          handle_faa_recv(buf, len);
        } else {
          handle_scewl_recv(buf, src_id, len);
        }
      }
    }
  }
}
