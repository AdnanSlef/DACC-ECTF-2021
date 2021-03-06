/*
 * MITRE 2021 Collegiate eCTF
 * SCEWL Bus Controller implementation
 *
 * 0xDACC
 * Adrian Self
 * Delaware Area Career Center
 *
 * This source file is part of our design for MITRE's 2021 Embedded System CTF (eCTF).
 * It provides secure networking capabilities to Scewl Enabled Devices including UAVs.
 */

#include "controller.h"
#include "sed.secret.h"

#ifdef DO_INCLUDE_AES
#include "aes.h"
#endif

#ifdef DO_INCLUDE_SB
#include "sb_all.h"
#endif


// message buffer
char buf[SCEWL_MAX_DATA_SZ+sizeof(secure_hdr_t)];

// CSPRNG state
sb_hmac_drbg_state_t drbg;

// reseed drbg if needed
void prep_drbg(void)
{
  if (sb_hmac_drbg_reseed_required(&drbg, 0x20)) {
    if (sb_hmac_drbg_generate(&drbg, ENTROPY[seed_idx], 32) != SB_SUCCESS) {
      //worst-case fallback entropy changer
      ENTROPY[seed_idx][seq%32] = NONCE[seq%16];
      ENTROPY[seed_idx][(seq+5)%32] = NONCE[(seq+3)%16];
    }
    seed_idx++; seed_idx %= NUM_SEEDS;
    sb_hmac_drbg_reseed(&drbg, ENTROPY[seed_idx], 32, (uint8_t *)&seq, 8);
  }
}


/*    Utilities    */
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

uint16_t scewl_to_depl(scewl_id_t scewl_id)
{
  if (scewl_id == SCEWL_BRDCST_ID) {
    return DEPL_BRDCST_ID;
  }
  for (uint16_t i=0; i<DEPL_COUNT; i++) {
    if (SCEWL_IDS_DB[i] == scewl_id) {
      return i;
    }
  }
  //scewl id not found
  return DEPL_ID;
}

scewl_id_t depl_to_scewl(uint16_t depl_id)
{
  if (depl_id < DEPL_COUNT) {
    return (scewl_id_t)SCEWL_IDS_DB[depl_id];
  }
  else {
    //invalid depl_id
    return (scewl_id_t)SCEWL_ID;
  }
}
/*******************/


_Bool l2_filter(intf_t * intf, scewl_id_t src_id, scewl_id_t tgt_id) {

  if (intf == SSS_INTF) {
    // always valid if from SSS
    return SCEWL_OK;
  }

  if (intf == CPU_INTF) {
    if (src_id != SCEWL_ID) {
      // don't impersonate or forward from other SEDs
      return SCEWL_ERR;
    }
    if (tgt_id == SCEWL_ID) {
      // don't send yourself a message
      return SCEWL_ERR;
    }
    // valid frame from CPU interface
    return SCEWL_OK;
  }

  if (intf == RAD_INTF) {
    if (src_id == SCEWL_ID) {
      // ignore all radio transmissions from self
      return SCEWL_ERR;
    }
    if (src_id == SCEWL_BRDCST_ID) {
      // broadcast is not a valid source
      return SCEWL_ERR;
    }
    if (tgt_id != SCEWL_BRDCST_ID && tgt_id != SCEWL_ID) {
      // ignore direct messages to other SEDs
      return SCEWL_ERR;
    }
    // valid frame from radio interface
    return SCEWL_OK;
  }

  // unknown interface
  return SCEWL_ERR;
}


int read_msg(intf_t *intf, char *data, scewl_id_t *src_id, scewl_id_t *tgt_id,
             size_t n, int blocking) {
  scewl_hdr_t hdr;
  int read, max;

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
  } while (hdr.magicS != 'S' || hdr.magicC != 'C');

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

  // discard unwanted frames
  if (!l2_filter(intf, hdr.src_id, hdr.tgt_id)) {
    return SCEWL_NO_MSG;
  }
  
  // return the length read
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


// left unmodified to comply with FAA specifications
int handle_faa_recv(char *data, uint16_t len) {
  return send_msg(CPU_INTF, SCEWL_FAA_ID, SCEWL_ID, len, data);
}


// left unmodified to comply with FAA specifications
int handle_faa_send(char *data, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, data);
}


int handle_registration(char *msg) {
  scewl_sss_msg_t *sss_msg = (scewl_sss_msg_t *)msg;
  if (sss_msg->op == SCEWL_SSS_REG) {
    return secure_register();
  }
  else if (sss_msg->op == SCEWL_SSS_DEREG) {
    return secure_deregister();
  }

  // bad op
  return SCEWL_ERR;
}


void sss_internal(int code, int type) {
  scewl_sss_msg_t msg;
  
  msg.dev_id = SCEWL_ID;
  
  switch(code) {
    case SCEWL_OK:
      msg.op = type? SCEWL_SSS_DEREG : SCEWL_SSS_REG;
      break;
    case SCEWL_ERR:
    case SCEWL_ALREADY:
      msg.op = SCEWL_SSS_ALREADY;
      break;
  }

  send_msg(CPU_INTF, SCEWL_SSS_ID, SCEWL_ID, sizeof(msg), (char *)&msg);
}


int secure_register(void) {
  sss_reg_req_t req;
  sss_reg_rsp_t *rsp = (sss_reg_rsp_t *)buf;
  scewl_id_t src_id, tgt_id;
  int len;
  struct AES_ctx aes_ctx;

  // check if already registered
  if (registered) {
    sss_internal(SCEWL_ALREADY, SCEWL_SSS_REG);
    //already registered
    return SCEWL_ERR;
  }

  // fill registration request
  req.basic.dev_id = SCEWL_ID;
  req.basic.op = SCEWL_SSS_REG;
  bcopy(req.auth, AUTH, sizeof(req.auth));
  
  // send registration request
  send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(req), (char *)&req);

  // receive registration response
  len = read_msg(SSS_INTF, (char *)rsp, &src_id, &tgt_id, sizeof(sss_reg_rsp_t), 1);
  if (len != sizeof(sss_reg_rsp_t) || rsp->basic.op != SCEWL_SSS_REG) {
    //did not receive a complete registration response
    sss_internal(SCEWL_ERR, SCEWL_SSS_REG);
    memset(rsp, 0, len);
    return SCEWL_ERR;
  }

  // verify source and target
  if (src_id != SCEWL_SSS_ID || tgt_id != SCEWL_ID || rsp->basic.dev_id != SCEWL_ID) {
    //this registration is not between the two intended parties
    sss_internal(SCEWL_ERR, SCEWL_SSS_REG);
    memset(rsp, 0, len);
    return SCEWL_ERR;
  }

  /*    process registration response    */
  // copy the new info
  bcopy((uint8_t *)SCEWL_IDS_DB, (uint8_t *)rsp->ids_db, sizeof(SCEWL_IDS_DB));
  seq = rsp->seq;
  bcopy((uint8_t *)KNOWN_SEQS, (uint8_t *)rsp->known_seqs, sizeof(KNOWN_SEQS));
  bcopy(depl_nonce, rsp->depl_nonce, sizeof(depl_nonce));

  // unlock ECC keys
  AES_init_ctx_iv(&aes_ctx, rsp->cryptkey, rsp->cryptiv);
  AES_CTR_xcrypt_buffer(&aes_ctx, (uint8_t *)ECC_PUBLICS_DB, sizeof(ECC_PUBLICS_DB));
  AES_CTR_xcrypt_buffer(&aes_ctx, (uint8_t *)BRDCST_PUBLIC, sizeof(BRDCST_PUBLIC));
  AES_CTR_xcrypt_buffer(&aes_ctx, (uint8_t *)ECC_PRIVATE_KEY, sizeof(ECC_PRIVATE_KEY));
  AES_CTR_xcrypt_buffer(&aes_ctx, (uint8_t *)BRDCST_PRIVATE_KEY, sizeof(BRDCST_PRIVATE_KEY));

  // scramble entropy
  AES_init_ctx_iv(&aes_ctx, rsp->entropky, rsp->entriv);
  AES_CTR_xcrypt_buffer(&aes_ctx, (uint8_t *)ENTROPY, sizeof(ENTROPY));
  AES_CTR_xcrypt_buffer(&aes_ctx, (uint8_t *)NONCE, sizeof(NONCE));
  /***************************************/

  // instantiate drbg
  if (sb_hmac_drbg_init(&drbg, ENTROPY[seed_idx], 32, NONCE, 16, depl_id_str, 8) != SB_SUCCESS) {
    //failed to initialize random generator
    sss_internal(SCEWL_ERR, SCEWL_SSS_REG);
    memset(rsp, 0, len);
    return SCEWL_ERR;
  }
  seed_idx++; seed_idx %= NUM_SEEDS;

  // successfully registered
  registered = 1;
  sss_internal(SCEWL_OK, SCEWL_SSS_REG);
  memset(rsp, 0, len);
  return SCEWL_OK;
}


int secure_deregister(void) {
  // declare locals
  sss_dereg_req_t *req = (sss_dereg_req_t *)buf;
  sss_dereg_rsp_t rsp;
  scewl_id_t src_id, tgt_id;
  int len;

  // verify state
  if (!registered) {
    sss_internal(SCEWL_ALREADY, SCEWL_SSS_DEREG);
    //not yet registered
    return SCEWL_ERR;
  }

  // repeatedly attempt deregistration
  do {

    // clear request and response
    memset(req, 0, sizeof(sss_dereg_req_t));
    memset(&rsp, 0, sizeof(rsp));

    // fill deregistration request
    req->basic.dev_id = SCEWL_ID;
    req->basic.op = SCEWL_SSS_DEREG;
    bcopy(req->auth, AUTH, sizeof(req->auth));
    req->seq = seq;
    bcopy((uint8_t *)req->known_seqs, (uint8_t *)KNOWN_SEQS, sizeof(req->known_seqs));

    // send deregistration request
    send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(sss_dereg_req_t), (char *)req);

    // receive deregistration response
    len = read_msg(SSS_INTF, (char *)&rsp, &src_id, &tgt_id, sizeof(rsp), 1);
    if (len != sizeof(rsp) || rsp.basic.op != SCEWL_SSS_DEREG) {
      //did not receive a complete deregistration response
      continue;
    }
    
    // verify source and target
    if (src_id != SCEWL_SSS_ID || tgt_id != SCEWL_ID || rsp.basic.dev_id != SCEWL_ID) {
      //this deregistration is not between the two intended parties
      continue;
    }

    // successfully deregistered
    registered = 0;

  } while (registered);

  // hang until power down
  sss_internal(SCEWL_OK, SCEWL_SSS_DEREG);
  while(1){/* spin merrily in circles */}

}


int secure_send(char *data, scewl_id_t tgt_scewl_id, uint16_t len)
{
  /*    declare local variables    */
  uint32_t i, j, jj, n, x;

  uint16_t tgt_depl_id;
  
  struct AES_ctx aes_ctx;
  uint8_t aeskey[16];
  uint8_t iv[16];
  
  sb_sw_context_t sb_ctx;
  sb_sha256_state_t sha;
  sb_hkdf_state_t hkdf;
  
  sb_sw_private_t *private;
  sb_sw_public_t *public;
  
  uint8_t xorkey[16];

  sb_sw_message_digest_t hash;
  sb_sw_shared_secret_t secret;
  sb_sw_signature_t sig;
  
  secure_hdr_t net_hdr;
  scewl_hdr_t frame_hdr;
  /*********************************/

  /*    just chill    */
  for (i = 0, n = len / 0x100 + (len%0x100?1:0); i < n; i++) {
    for (j = 0; j < SLOTH; j++) {
      for (jj = 0; jj < ONE_SECOND; jj++) {
        x ^= 0xC001DACC;
        x += 0xC001DACC;
      }
    }
  }
  //make sure this block isn't optimized out
  *(uint32_t *)&frame_hdr = x;
  /********************/

  /*    check for problems    */
  //ensure registration has been completed
  if(!registered) {
    //SED has yet to register successfully
    return SCEWL_ERR;
  }

  // validate input length
  if (len > SCEWL_MAX_DATA_SZ) {
    //requested length is too long
    return SCEWL_ERR;
  }

  // don't send message to self
  tgt_depl_id = scewl_to_depl(tgt_scewl_id);
  if (tgt_depl_id == DEPL_ID) {
    //attempted to send message to self
    return SCEWL_ERR;
  }

  // reseed DRBG if needed
  prep_drbg();
  if (sb_hmac_drbg_reseed_required(&drbg, 0x20)) {
    //failed to reseed drbg
    return SCEWL_ERR;
  }
  /****************************/

  /*    encrypt a message    */ 
  //generate secure randomness for aes
  sb_hmac_drbg_generate(&drbg, aeskey, 16);
  sb_hmac_drbg_generate(&drbg, iv, 16);

  // initialize AES context
  AES_init_ctx_iv(&aes_ctx, aeskey, iv);

  // encrypt buffer (in-place)
  AES_CTR_xcrypt_buffer(&aes_ctx, data, len);
  /***************************/

  /*    establish shared secret    */
  private = (sb_sw_private_t *)ECC_PRIVATE_KEY;
  if (tgt_depl_id == DEPL_BRDCST_ID) {
    public = (sb_sw_public_t *)BRDCST_PUBLIC;
  }
  else {
    public = (sb_sw_public_t *)ECC_PUBLICS_DB[tgt_depl_id];
  }

  if(sb_sw_shared_secret(&sb_ctx, &secret, private, public, &drbg, SB_SW_CURVE_P256, 1) != SB_SUCCESS)
  {
    //unable to establish shared secret
    return SCEWL_ERR;
  }
  /*********************************/

  /*    encrypt aes key    */
  sb_hkdf_extract(&hkdf, NULL, 0, (uint8_t *)&secret, sizeof(secret));
  sb_hkdf_expand(&hkdf, NULL, 0, xorkey, sizeof(xorkey));
  if (xorkey[0]+xorkey[1]+xorkey[2] == 0) {
    //we're not masking much; did something go wrong?
    return SCEWL_ERR;
  }
  
  // xor key with aes key
  bxor(aeskey, xorkey, sizeof(aeskey));
  /*************************/

  /*    pack network packet header    */
  net_hdr.src   = DEPL_ID;
  net_hdr.tgt   = tgt_depl_id;
  net_hdr.ctlen = len;
  net_hdr.seq   = seq++;
  bcopy(net_hdr.key, aeskey, 16);
  bcopy(net_hdr.iv, iv, 16);
  /************************************/

  /*    sign network packet    */
  sb_sha256_init(&sha);
  //network packet header
  sb_sha256_update(&sha, (uint8_t *)&net_hdr + sizeof(net_hdr.sig), sizeof(net_hdr)-sizeof(net_hdr.sig));
  //ciphertext
  sb_sha256_update(&sha, data, len);
  //deployment nonce
  sb_sha256_update(&sha, depl_nonce, sizeof(depl_nonce));
  sb_sha256_finish(&sha, &hash);
  
  if (sb_sw_sign_message_digest(&sb_ctx, &sig, private, &hash, &drbg, SB_SW_CURVE_P256, 1) != SB_SUCCESS) {
    //failed to sign network packet
    return SCEWL_ERR;
  }
  bcopy(net_hdr.sig, (uint8_t *)&sig, sizeof(net_hdr.sig));
  /*****************************/

  /*    pack frame header    */
  frame_hdr.magicS = 'S';
  frame_hdr.magicC = 'C';
  frame_hdr.src_id = SCEWL_ID;
  frame_hdr.tgt_id = tgt_scewl_id;
  frame_hdr.len    = sizeof(net_hdr) + net_hdr.ctlen;
  /***************************/

  /*    send bytes on outbound interface    */
  // send frame header
  intf_write(RAD_INTF, (char *)&frame_hdr, sizeof(frame_hdr));
  
  // send packet header
  intf_write(RAD_INTF, (char *)&net_hdr, sizeof(net_hdr));
  
  // send ciphertext
  intf_write(RAD_INTF, data, len);
  /******************************************/

  return SCEWL_OK;
}


int secure_recv(char *data, scewl_id_t src_scewl_id, uint16_t len, _Bool broadcast)
{
  /*    declare local variables    */
  secure_hdr_t *net_hdr;
  uint8_t *xtext;

  sb_sw_public_t *public;
  sb_sw_private_t *private;
  
  sb_sw_context_t sb_ctx;
  sb_sha256_state_t sha;
  sb_hkdf_state_t hkdf;
  
  sb_sw_message_digest_t hash;
  sb_sw_shared_secret_t secret;
  
  uint8_t xorkey[16];
  
  struct AES_ctx aes_ctx;
  /*********************************/

  /*    check for problems    */
  net_hdr = (secure_hdr_t *)data;
  
  // ensure registration has been completed
  if(!registered) {
    //SED has yet to register successfully
    return SCEWL_ERR;
  }

  // validate input length
  if (len > sizeof(buf)) {
    //requested length is too long
    return SCEWL_ERR;
  }

  // verify source
  if ( src_scewl_id == SCEWL_ID || depl_to_scewl(net_hdr->src) != src_scewl_id ) {
    //scewl id does not match deployment id
    return SCEWL_ERR;
  }

  // check length
  if ( net_hdr->ctlen != len - sizeof(secure_hdr_t) ) {
    //scewl frame length field not consistent with network packet length field
    return SCEWL_ERR;
  }

  // prevent replay
  if ( net_hdr->seq <= KNOWN_SEQS[net_hdr->src] ) {
    //this network packet is expired or has already been processed
    return SCEWL_ERR;
  }
  
  // reseed DRBG if needed
  prep_drbg();
  if (sb_hmac_drbg_reseed_required(&drbg, 0x20)) {
    //failed to reseed drbg
    return SCEWL_ERR;
  }
  /****************************/

  /*    check signature    */
  public = (sb_sw_public_t *)ECC_PUBLICS_DB[net_hdr->src];
  xtext = data + sizeof(secure_hdr_t);

  sb_sha256_init(&sha);
  //verify network packet header integrity
  sb_sha256_update(&sha, (uint8_t *)net_hdr + sizeof(sb_sw_signature_t), sizeof(secure_hdr_t)-sizeof(sb_sw_signature_t));
  //verify ciphertext integrity
  sb_sha256_update(&sha, xtext, net_hdr->ctlen);
  //deployment nonce
  sb_sha256_update(&sha, depl_nonce, sizeof(depl_nonce));
  sb_sha256_finish(&sha, &hash);

  //reject packets which fail integrity check
  if ( sb_sw_verify_signature(&sb_ctx, net_hdr->sig, public, &hash, &drbg, SB_SW_CURVE_P256, 1) != SB_SUCCESS ) {
    //signature invalid
    return SCEWL_ERR;
  }
  /*************************/

  /*    derive shared secret    */
  if (broadcast) {
    private = (sb_sw_private_t *)BRDCST_PRIVATE_KEY;
  }
  else {
    private = (sb_sw_private_t *)ECC_PRIVATE_KEY;
  }

  if(sb_sw_shared_secret(&sb_ctx, &secret, private, public, &drbg, SB_SW_CURVE_P256, 1) != SB_SUCCESS) {
    //failed to establish shared secret
    return SCEWL_ERR;
  }
  /******************************/

  /*    decrypt aes key    */
  //derive xor key from shared secret
  sb_hkdf_extract(&hkdf, NULL, 0, (uint8_t *)&secret, sizeof(secret));
  sb_hkdf_expand(&hkdf, NULL, 0, xorkey, sizeof(xorkey));
  
  //deduce aes key
  bxor(net_hdr->key, xorkey, 16);
  /*************************/

  /*    decrypt message    */
  //initialize AES context
  AES_init_ctx_iv(&aes_ctx, net_hdr->key, net_hdr->iv);

  //decrypt in place
  AES_CTR_xcrypt_buffer(&aes_ctx, xtext, net_hdr->ctlen);
  /*************************/

  /*    process message    */
  //prevent replay of this or older messages
  KNOWN_SEQS[net_hdr->src] = net_hdr->seq;
  
  //pass message to the CPU
  send_msg(CPU_INTF, src_scewl_id, SCEWL_ID, net_hdr->ctlen, xtext);

  //clear buffer for future use
  memset(data, 0, len);
  /*************************/

  return SCEWL_OK;
}


int main() {
  int len;
  uint16_t src_id, tgt_id;

  // initialize interfaces
  intf_init(CPU_INTF);
  intf_init(SSS_INTF);
  intf_init(RAD_INTF);

  // serve forever
  while (1) {
    // register with SSS
    len = read_msg(CPU_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

    if (tgt_id == SCEWL_SSS_ID) {
      handle_registration(buf);
    }

    // serve while registered
    while (registered) {

      // handle outgoing message from CPU
      if (intf_avail(CPU_INTF)) {
        // Read message from CPU
        len = read_msg(CPU_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);
        if(len==SCEWL_NO_MSG) continue;

        if (tgt_id == SCEWL_BRDCST_ID) {
          secure_send(buf, tgt_id, len);
        } else if (tgt_id == SCEWL_SSS_ID) {
          handle_registration(buf);
        } else if (tgt_id == SCEWL_FAA_ID) {
          handle_faa_send(buf, len);
        } else {
          secure_send(buf, tgt_id, len);
        }

        continue;
      }

      // handle incoming radio message
      if (intf_avail(RAD_INTF)) {
        // Read message from antenna
        len = read_msg(RAD_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);
        if(len == SCEWL_NO_MSG) continue;

        if (tgt_id == SCEWL_BRDCST_ID) {
          if (src_id == SCEWL_FAA_ID) {
            handle_faa_recv(buf, len);
          }
          secure_recv(buf, src_id, len, 1);
        } else if (src_id == SCEWL_FAA_ID) {
          handle_faa_recv(buf, len);
        } else {
          secure_recv(buf, src_id, len, 0);
        }
      }
    }
  }
}
