/*
 * 2021 Collegiate eCTF
 * Example echo client
 * Ben Janis
 *
 * (c) 2021 The MITRE Corporation
 *
 * This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 */

#include "scewl_bus_driver/scewl_bus.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define BUF_SZ 0x4000

// SCEWL_ID and TGT_ID need to be defined at compile
#ifndef TGT_ID
#warning TGT_ID not defined, using bad default of 0xffff
#define TGT_ID ((scewl_id_t)0xffff)
#endif


// trust me, it's easier to get the boot reference flag by
// following the instructions than to try to untangle this
// NOTE: you're not allowed to do this in your code
typedef uint32_t aErjfkdfru;const uint32_t flag_as[]={0x1ffe4b6,0x3098ac,
0x2f56101,0x11a38bb,0x485124,0x11644a7,0x3c74e8,0x3c74e8,0x2f56101,0x2ca498,
0x3098ac,0x1fbf0a2,0x11a38bb,0x1ffe4b6,0x3098ac,0x3c74e8,0x11a38bb,0x11a38bb,
0x1ffe4b6,0x1ffe4b6,0x1cc7fb2,0x1fbf0a2,0x51bd0,0x51bd0,0x1ffe4b6,0x1d073c6,
0x2179d2e,0};const uint32_t flag_bs[]={0x138e798,0x2cdbb14,0x1f9f376,0x23bcfda,
0x1d90544,0x1cad2d2,0x860e2c,0x860e2c,0x1f9f376,0x25cbe0c,0x2cdbb14,0xc7ea90,
0x23bcfda,0x138e798,0x2cdbb14,0x860e2c,0x23bcfda,0x23bcfda,0x138e798,0x138e798,
0x2b15630,0xc7ea90,0x18d7fbc,0x18d7fbc,0x138e798,0x3225338,0x4431c8,0};
typedef int skerufjp; skerufjp siNfidpL(skerufjp verLKUDSfj){aErjfkdfru 
ubkerpYBd=12+1;skerufjp xUrenrkldxpxx=2253667944%0x432a1f32;aErjfkdfru UfejrlcpD=
1361423303;verLKUDSfj=(verLKUDSfj+0x12345678)%60466176;while(
xUrenrkldxpxx--!=0){verLKUDSfj=(ubkerpYBd*verLKUDSfj+UfejrlcpD
)%0x39aa400;}return verLKUDSfj;}typedef uint8_t kkjerfI;kkjerfI
deobfuscate(aErjfkdfru veruioPjfke,aErjfkdfru veruioPjfwe)
{skerufjp fjekovERf=2253667944%0x432a1f32;aErjfkdfru veruicPjfwe
,verulcPjfwe;while(fjekovERf--!=0){veruioPjfwe=(veruioPjfwe
-siNfidpL(veruioPjfke))%0x39aa400;veruioPjfke=(veruioPjfke-
siNfidpL(veruioPjfwe))%60466176;}veruicPjfwe=(veruioPjfke+
0x39aa400)%60466176;verulcPjfwe=(veruioPjfwe+
60466176)%0x39aa400;return veruicPjfwe*60466176+verulcPjfwe-89;}


int main(void) {
  scewl_id_t src_id, tgt_id;
  uint16_t len;
  char msg[BUF_SZ+1] = "hello to world!~";
  char data[BUF_SZ+1];
  struct timeval start, end;
  double t1, t2;

  for (int i=1; i < 0x400; i++) {
    memcpy(msg+0x10*i, msg, 16);
  }
  msg[0] = 'A';
  msg[BUF_SZ-1] = 'Z';
  msg[BUF_SZ] = '\x00';
  data[BUF_SZ] = '\x00';

  // open log file
  FILE *log = stderr;
  // NOTE: you can write to a file inside the Docker container instead:
  // FILE *log = fopen("cpu.log", "a");

  // initialize SCEWL
  scewl_init();

  // register
  if (scewl_register() != SCEWL_OK) {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK) {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK) {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }
  
  sleep(10 * (SCEWL_ID-10));

  /* test long message */
  fprintf(log, "%d Sending long hello...\n", SCEWL_ID);
  gettimeofday(&start, NULL);
  scewl_send(TGT_ID, BUF_SZ, msg);

  // receive response (block until response received)
  fprintf(log, "%d Waiting for response...\n", SCEWL_ID);
  scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);
  gettimeofday(&end, NULL);
  t1 = start.tv_sec + (start.tv_usec/1000000.0);
  t2 = end.tv_sec + (end.tv_usec/1000000.0);
  fprintf(log, data);
  fprintf(log, "\n");
  fprintf(log, "Time used for %d to send and receive: %f\n", SCEWL_ID, t2-t1);

  // check if response matches
  if (!strncmp(msg, data, BUF_SZ)) {
    // decode and print flag
    uint8_t flag[32] = {0};
    for (int i = 0; flag_as[i]; i++) {
      flag[i] = deobfuscate(flag_as[i], flag_bs[i]);
      flag[i+1] = 0;
    }
    fprintf(log, "Congrats on booting the %d system! Press <enter> on the FAA transceiver to view your flag!\n", SCEWL_ID);
    scewl_send(SCEWL_FAA_ID, strlen(flag), flag);
  } else {
    fprintf(log, "Bad response to %d!\n", SCEWL_ID);
  }
  /***********************/

  /* test short message *
  fprintf(log, "%d Sending short hello...\n", SCEWL_ID);
  gettimeofday(&start, NULL);
  scewl_send(TGT_ID, 0x100, msg);

  // receive response (block until response received)
  fprintf(log, "%d Waiting for response...\n", SCEWL_ID);
  scewl_recv(data, &src_id, &tgt_id, 0x100, 1);
  gettimeofday(&end, NULL);
  t1 = start.tv_sec + (start.tv_usec/1000000.0);
  t2 = end.tv_sec + (end.tv_usec/1000000.0);
  fprintf(log, data);
  fprintf(log, "\n");
  fprintf(log, "Time used for %d to send and receive: %f\n", SCEWL_ID, t2-t1);

  // check if response matches
  if (!strncmp(msg, data, 0x100)) {
    // decode and print flag
    uint8_t flag[32] = {0};
    for (int i = 0; flag_as[i]; i++) {
      flag[i] = deobfuscate(flag_as[i], flag_bs[i]);
      flag[i+1] = 0;
    }
    fprintf(log, "Congrats on booting the system! Press <enter> on the FAA transceiver to view your flag!\n");
    scewl_send(SCEWL_FAA_ID, strlen(flag), flag);
  } else {
    fprintf(log, "Bad response!\n");
  }
  /***********************/


  /**********************/

  sleep(1000);

  // deregister
  fprintf(log, "Deregistering %d...\n", SCEWL_ID);
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");
}
